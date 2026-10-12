use crate::{now_ms, pattern_byte, stats};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

fn http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}

pub async fn http(base: &str, bearer: &str) -> anyhow::Result<Value> {
    let client = http_client()?;
    let health = client.get(format!("{base}/healthz")).send().await;
    let mcp = client
        .post(format!("{base}/mcp"))
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await;
    let token = client
        .post(format!("{base}/token"))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_assertion", "probe"),
        ])
        .send()
        .await;
    let bearer_auth = client
        .get(format!("{base}/auth"))
        .bearer_auth(bearer)
        .send()
        .await;
    let basic_auth = client
        .get(format!("{base}/auth"))
        .basic_auth("probe", Some("probe"))
        .send()
        .await;
    let big = big(base, 8 * 1024 * 1024).await;
    Ok(json!({
        "test": "http",
        "base": base,
        "healthz": outcome(health).await,
        "mcpPost": outcome(mcp).await,
        "formToken": outcome(token).await,
        "bearerAuth": outcome(bearer_auth).await,
        "basicAuth": outcome(basic_auth).await,
        "body8mib": big.unwrap_or_else(|e| json!({"error": e.to_string()})),
    }))
}

async fn outcome(response: reqwest::Result<reqwest::Response>) -> Value {
    match response {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let body: Value = serde_json::from_str(&body)
                .unwrap_or(json!(body.chars().take(200).collect::<String>()));
            json!({"status": status, "body": body})
        }
        Err(error) => json!({"error": error.to_string()}),
    }
}

pub async fn big(base: &str, bytes: u64) -> anyhow::Result<Value> {
    let started = Instant::now();
    let response = http_client()?
        .get(format!("{base}/big?bytes={bytes}"))
        .send()
        .await?
        .error_for_status()?;
    let mut stream = response.bytes_stream();
    let (mut received, mut mismatch_at) = (0u64, None);
    let mut digest = Sha256::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if mismatch_at.is_none()
            && let Some(i) = chunk
                .iter()
                .enumerate()
                .position(|(i, b)| *b != pattern_byte(received + i as u64))
        {
            mismatch_at = Some(received + i as u64);
        }
        digest.update(&chunk);
        received += chunk.len() as u64;
    }
    let secs = started.elapsed().as_secs_f64();
    Ok(json!({
        "test": "big",
        "expectedBytes": bytes,
        "receivedBytes": received,
        "contentMatches": mismatch_at.is_none() && received == bytes,
        "firstMismatch": mismatch_at,
        "seconds": secs,
        "mibPerS": received as f64 / 1048576.0 / secs,
        "sha256": digest.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>(),
    }))
}

pub async fn sse(
    base: &str,
    seconds: u64,
    interval_ms: u64,
    streams: usize,
) -> anyhow::Result<Value> {
    let count = seconds * 1000 / interval_ms.max(1);
    let url = format!("{base}/sse?interval_ms={interval_ms}&count={count}");
    let mut tasks = Vec::new();
    for _ in 0..streams {
        let url = url.clone();
        tasks.push(tokio::spawn(async move { one_sse(&url).await }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await?);
    }
    let complete = results
        .iter()
        .filter(|r| r.get("received").and_then(Value::as_u64) == Some(count))
        .count();
    let worst_gap = results
        .iter()
        .filter_map(|r| r.get("maxGapMs").and_then(Value::as_u64))
        .max();
    let worst_p99 = results
        .iter()
        .filter_map(|r| r.pointer("/latenessMs/p99").and_then(Value::as_u64))
        .max();
    Ok(json!({
        "test": "sse",
        "url": url,
        "streams": streams,
        "expectedPerStream": count,
        "completeStreams": complete,
        "worstMaxGapMs": worst_gap,
        "worstP99LatenessMs": worst_p99,
        "firstStream": results.first(),
        "errors": results.iter().filter_map(|r| r.get("error")).collect::<Vec<_>>(),
    }))
}

async fn one_sse(url: &str) -> Value {
    let response = match http_client().map(|c| c.get(url)) {
        Ok(request) => request.send().await,
        Err(error) => return json!({"error": error.to_string()}),
    };
    let response = match response.and_then(|r| r.error_for_status()) {
        Ok(response) => response,
        Err(error) => return json!({"error": error.to_string()}),
    };
    let mut stream = response.bytes_stream();
    let (mut buffer, mut lateness, mut arrivals) = (String::new(), Vec::new(), Vec::new());
    let mut error = None;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => buffer.push_str(&String::from_utf8_lossy(&chunk)),
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
        while let Some(end) = buffer.find("\n\n") {
            let event: String = buffer.drain(..end + 2).collect();
            if let Some(data) = event.lines().find_map(|l| l.strip_prefix("data:"))
                && let Ok(value) = serde_json::from_str::<Value>(data.trim())
                && let Some(server_ms) = value.get("serverMs").and_then(Value::as_u64)
            {
                let now = now_ms();
                arrivals.push(now);
                lateness.push(now.saturating_sub(server_ms));
            }
        }
    }
    json!({
        "received": arrivals.len(),
        "latenessMs": stats::summarize(lateness),
        "maxGapMs": stats::max_gap(&arrivals),
        "error": error,
    })
}

pub async fn frames(
    base: &str,
    seconds: u64,
    interval_ms: u64,
    frame_bytes: usize,
) -> anyhow::Result<Value> {
    let count = seconds * 1000 / interval_ms.max(1);
    let url =
        format!("{base}/frames?interval_ms={interval_ms}&count={count}&frame_bytes={frame_bytes}");
    let response = http_client()?.get(&url).send().await?.error_for_status()?;
    let mut stream = response.bytes_stream();
    let (mut buffer, mut lateness, mut arrivals) = (Vec::<u8>::new(), Vec::new(), Vec::new());
    let mut error = None;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => buffer.extend_from_slice(&chunk),
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
        while buffer.len() >= 4 {
            let len = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
            if buffer.len() < 4 + len {
                break;
            }
            let server_ms = u64::from_be_bytes(buffer[12..20].try_into().unwrap());
            let now = now_ms();
            arrivals.push(now);
            lateness.push(now.saturating_sub(server_ms));
            buffer.drain(..4 + len);
        }
    }
    Ok(json!({
        "test": "frames",
        "url": url,
        "expected": count,
        "received": arrivals.len(),
        "frameBytes": frame_bytes,
        "latenessMs": stats::summarize(lateness),
        "maxGapMs": stats::max_gap(&arrivals),
        "error": error,
    }))
}

pub async fn ws(url: &str, seconds: u64, interval_ms: u64) -> anyhow::Result<Value> {
    let (socket, response) = match tokio_tungstenite::connect_async(url).await {
        Ok(connected) => connected,
        Err(error) => {
            return Ok(json!({"test": "ws", "url": url, "connectError": error.to_string()}));
        }
    };
    let upgrade_status = response.status().as_u16();
    let (mut sink, mut source) = socket.split();
    let count = seconds * 1000 / interval_ms.max(1);
    let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
    let (mut sent, mut rtts, mut error) = (0u64, Vec::new(), None);
    while (rtts.len() as u64) < count {
        tokio::select! {
            _ = interval.tick(), if sent < count => {
                let text = json!({"seq": sent, "sentMs": now_ms()}).to_string();
                if let Err(e) = sink.send(Message::Text(text.into())).await { error = Some(e.to_string()); break; }
                sent += 1;
            }
            message = source.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    if let Ok(value) = serde_json::from_str::<Value>(&text)
                        && let Some(sent_ms) = value.get("sentMs").and_then(Value::as_u64)
                    {
                        rtts.push(now_ms().saturating_sub(sent_ms));
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => { error = Some(e.to_string()); break; }
                None => { error = Some("closed by peer".into()); break; }
            }
        }
    }
    Ok(json!({
        "test": "ws",
        "url": url,
        "upgradeStatus": upgrade_status,
        "expected": count,
        "echoed": rtts.len(),
        "rttMs": stats::summarize(rtts),
        "error": error,
    }))
}
