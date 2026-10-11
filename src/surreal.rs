use crate::{now_ms, stats};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use surrealdb::{
    Notification, Surreal, engine::remote::ws::Ws, opt::auth::Root, types::SurrealValue,
};

#[derive(Clone, Debug, Serialize, Deserialize, SurrealValue)]
struct Row {
    seq: i64,
    sent_ms: i64,
}

pub async fn run(
    address: &str,
    user: String,
    pass: String,
    seconds: u64,
    interval_ms: u64,
) -> anyhow::Result<Value> {
    let db = Surreal::new::<Ws>(address.to_owned()).await?;
    db.signin(Root {
        username: user,
        password: pass,
    })
    .await?;
    db.use_ns("probe").use_db("probe").await?;
    let run_id = now_ms();
    let table = format!("probe_{run_id}");
    db.query(format!("DEFINE TABLE {table} SCHEMALESS"))
        .await?
        .check()?;

    let mut response = db
        .query(format!("LIVE SELECT * FROM {table}"))
        .await?
        .check()?;
    let mut live = response.stream::<Notification<Row>>(0)?;

    let count = seconds * 1000 / interval_ms.max(1);
    let writer = {
        let db = db.clone();
        let table = table.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
            let mut errors = 0u64;
            for seq in 0..count {
                interval.tick().await;
                let row = Row {
                    seq: seq as i64,
                    sent_ms: now_ms() as i64,
                };
                let created: Result<Option<Row>, _> = db.create(table.as_str()).content(row).await;
                if created.is_err() {
                    errors += 1;
                }
            }
            errors
        })
    };

    let (mut latency, mut arrivals, mut error) = (Vec::new(), Vec::new(), None);
    let deadline = tokio::time::sleep(Duration::from_millis(seconds * 1000 + 10_000));
    tokio::pin!(deadline);
    while (latency.len() as u64) < count {
        tokio::select! {
            notification = live.next() => match notification {
                Some(Ok(notification)) => {
                    let now = now_ms();
                    arrivals.push(now);
                    latency.push(now.saturating_sub(notification.data.sent_ms as u64));
                }
                Some(Err(e)) => { error = Some(e.to_string()); break; }
                None => { error = Some("live stream ended".into()); break; }
            },
            _ = &mut deadline => { error = Some("deadline before all notifications".into()); break; }
        }
    }
    let write_errors = writer.await?;
    db.query(format!("REMOVE TABLE {table}")).await?.check()?;
    Ok(json!({
        "test": "surreal",
        "address": address,
        "expected": count,
        "notified": latency.len(),
        "write_errors": write_errors,
        "live_latency_ms": stats::summarize(latency),
        "max_gap_ms": stats::max_gap(&arrivals),
        "error": error,
    }))
}
