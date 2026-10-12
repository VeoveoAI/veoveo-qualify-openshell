use crate::{now_ms, pattern_byte};
use axum::{
    Form, Json, Router,
    body::Body,
    extract::{
        Query,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, header},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use bytes::Bytes;
use futures::stream::{self, Stream, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, convert::Infallible, net::SocketAddr, time::Duration};

pub async fn serve(http: SocketAddr, grpc: SocketAddr) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/mcp", post(mcp))
        .route("/token", post(token))
        .route("/auth", get(auth))
        .route("/big", get(big))
        .route("/sse", get(sse))
        .route("/frames", get(frames))
        .route("/ws", get(ws));
    let listener = tokio::net::TcpListener::bind(http).await?;
    eprintln!("probe http on {http}, grpc on {grpc}");
    let http_task = tokio::spawn(async move { axum::serve(listener, app).await });
    let grpc_task = tokio::spawn(crate::grpc::serve(grpc));
    tokio::select! {
        result = http_task => result??,
        result = grpc_task => result??,
    }
    Ok(())
}

fn authorization_kind(headers: &HeaderMap) -> Value {
    match headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        None => json!("absent"),
        Some(v) if v.starts_with("Bearer ") => json!({
            "bearerLen": v.len() - 7,
            "bearerSha256": crate::sha256_hex(&v.as_bytes()["Bearer ".len()..]),
        }),
        Some(v) => json!({"otherScheme": v.split(' ').next().unwrap_or("")}),
    }
}

async fn mcp(Json(request): Json<Value>) -> Json<Value> {
    Json(json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": {"method": request.get("method"), "serverMs": now_ms()},
    }))
}

async fn token(headers: HeaderMap, Form(fields): Form<BTreeMap<String, String>>) -> Json<Value> {
    Json(json!({
        "fields": fields.keys().collect::<Vec<_>>(),
        "authorization": authorization_kind(&headers),
    }))
}

async fn auth(headers: HeaderMap) -> Json<Value> {
    Json(json!({"authorization": authorization_kind(&headers)}))
}

#[derive(Deserialize)]
struct BigQuery {
    bytes: u64,
}

async fn big(Query(query): Query<BigQuery>) -> Response {
    const CHUNK: u64 = 64 * 1024;
    let total = query.bytes;
    let chunks = stream::unfold(0u64, move |offset| async move {
        if offset >= total {
            return None;
        }
        let len = CHUNK.min(total - offset);
        let chunk: Vec<u8> = (offset..offset + len).map(pattern_byte).collect();
        Some((Ok::<_, Infallible>(Bytes::from(chunk)), offset + len))
    });
    (
        [(header::CONTENT_LENGTH, total.to_string())],
        Body::from_stream(chunks),
    )
        .into_response()
}

#[derive(Deserialize)]
struct StreamQuery {
    interval_ms: u64,
    count: u64,
    #[serde(default)]
    frame_bytes: usize,
}

fn ticks(interval_ms: u64, count: u64) -> impl Stream<Item = u64> {
    let interval = tokio::time::interval(Duration::from_millis(interval_ms));
    stream::unfold((interval, 0u64), move |(mut interval, seq)| async move {
        if seq >= count {
            return None;
        }
        interval.tick().await;
        Some((seq, (interval, seq + 1)))
    })
}

async fn sse(
    Query(query): Query<StreamQuery>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let events = ticks(query.interval_ms, query.count).map(|seq| {
        Ok(Event::default().data(json!({"seq": seq, "serverMs": now_ms()}).to_string()))
    });
    Sse::new(events).keep_alive(KeepAlive::default())
}

async fn frames(Query(query): Query<StreamQuery>) -> Response {
    let frame_bytes = query.frame_bytes.max(16);
    let body = ticks(query.interval_ms, query.count).map(move |seq| {
        let mut frame = Vec::with_capacity(4 + frame_bytes);
        frame.extend_from_slice(&(frame_bytes as u32).to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.extend_from_slice(&now_ms().to_be_bytes());
        frame.resize(4 + frame_bytes, 0xA5);
        Ok::<_, Infallible>(Bytes::from(frame))
    });
    (
        [(header::CONTENT_TYPE, "application/vnd.veoveo.probe-frames")],
        Body::from_stream(body),
    )
        .into_response()
}

async fn ws(upgrade: WebSocketUpgrade) -> Response {
    upgrade.on_upgrade(echo)
}

async fn echo(mut socket: WebSocket) {
    while let Some(Ok(message)) = socket.recv().await {
        let reply = match message {
            Message::Text(text) => {
                let mut value: Value = serde_json::from_str(&text).unwrap_or(json!({}));
                value["serverMs"] = json!(now_ms());
                Message::Text(value.to_string().into())
            }
            Message::Ping(payload) => Message::Pong(payload),
            Message::Close(_) => break,
            _ => continue,
        };
        if socket.send(reply).await.is_err() {
            break;
        }
    }
}
