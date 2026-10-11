use crate::{now_ms, stats};
use futures::{Stream, StreamExt};
use serde_json::{Value, json};
use std::{net::SocketAddr, pin::Pin, time::Duration};
use tonic::{Request, Response, Status, Streaming};

pub mod pb {
    tonic::include_proto!("probe");
}
use pb::{
    Ping, Pong, Tick, TickRequest,
    probe_client::ProbeClient,
    probe_server::{Probe, ProbeServer},
};

#[derive(Default)]
struct Service;

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[tonic::async_trait]
impl Probe for Service {
    type ChatStream = BoxStream<Pong>;
    type TicksStream = BoxStream<Tick>;

    async fn chat(
        &self,
        request: Request<Streaming<Ping>>,
    ) -> Result<Response<Self::ChatStream>, Status> {
        let pongs = request.into_inner().map(|ping| {
            ping.map(|ping| Pong {
                seq: ping.seq,
                sent_ms: ping.sent_ms,
                server_ms: now_ms(),
            })
        });
        Ok(Response::new(Box::pin(pongs)))
    }

    async fn ticks(
        &self,
        request: Request<TickRequest>,
    ) -> Result<Response<Self::TicksStream>, Status> {
        let TickRequest { interval_ms, count } = request.into_inner();
        Ok(Response::new(Box::pin(
            tick_stream(interval_ms, count).map(Ok),
        )))
    }
}

fn tick_stream(interval_ms: u64, count: u64) -> impl Stream<Item = Tick> + Send {
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms.max(1)));
        for seq in 0..count {
            interval.tick().await;
            if sender
                .send(Tick {
                    seq,
                    server_ms: now_ms(),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(receiver)
}

pub async fn serve(addr: SocketAddr) -> anyhow::Result<()> {
    tonic::transport::Server::builder()
        .add_service(ProbeServer::new(Service))
        .serve(addr)
        .await?;
    Ok(())
}

pub async fn client(url: &str, seconds: u64, interval_ms: u64) -> anyhow::Result<Value> {
    let mut client = ProbeClient::connect(url.to_owned()).await?;
    let count = seconds * 1000 / interval_ms.max(1);

    let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
    let pings = async_stream_pings(count, interval_ms);
    let mut pongs = client.chat(Request::new(pings)).await?.into_inner();
    let mut ticks = client
        .clone()
        .ticks(TickRequest { interval_ms, count })
        .await?
        .into_inner();

    let (mut rtts, mut tick_lateness, mut tick_arrivals) = (Vec::new(), Vec::new(), Vec::new());
    let (mut chat_error, mut tick_error) = (None, None);
    let (mut chat_done, mut ticks_done) = (false, false);
    while !(chat_done && ticks_done) {
        tokio::select! {
            pong = pongs.message(), if !chat_done => match pong {
                Ok(Some(pong)) => rtts.push(now_ms().saturating_sub(pong.sent_ms)),
                Ok(None) => chat_done = true,
                Err(status) => { chat_error = Some(status.to_string()); chat_done = true; }
            },
            tick = ticks.message(), if !ticks_done => match tick {
                Ok(Some(tick)) => {
                    let now = now_ms();
                    tick_arrivals.push(now);
                    tick_lateness.push(now.saturating_sub(tick.server_ms));
                }
                Ok(None) => ticks_done = true,
                Err(status) => { tick_error = Some(status.to_string()); ticks_done = true; }
            },
            _ = interval.tick() => {}
        }
    }
    Ok(json!({
        "test": "grpc",
        "url": url,
        "expected": count,
        "chat_rtt_ms": stats::summarize(rtts),
        "chat_error": chat_error,
        "ticks_lateness_ms": stats::summarize(tick_lateness),
        "ticks_max_gap_ms": stats::max_gap(&tick_arrivals),
        "ticks_error": tick_error,
    }))
}

fn async_stream_pings(count: u64, interval_ms: u64) -> impl Stream<Item = Ping> + Send {
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
        for seq in 0..count {
            interval.tick().await;
            if sender
                .send(Ping {
                    seq,
                    sent_ms: now_ms(),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(receiver)
}
