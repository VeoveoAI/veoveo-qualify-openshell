//! Runs queries, holds a session advisory lock and follows writes through LISTEN/NOTIFY
//! over the PostgreSQL wire protocol, the connection profile of a Veoveo component.

use crate::{now_ms, stats};
use anyhow::Context;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions, Connection, PgConnection,
    postgres::{PgConnectOptions, PgListener, PgPoolOptions},
};
use std::{str::FromStr, time::Duration};

/// Rows written by every probe run. The trigger announces each row on the channel
/// `probe_<run>` with a JSON payload.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS probe_row (
    run bigint NOT NULL,
    seq bigint NOT NULL,
    sent_ms bigint NOT NULL,
    PRIMARY KEY (run, seq)
);
CREATE OR REPLACE FUNCTION probe_row_notify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_notify('probe_' || NEW.run, json_build_object('seq', NEW.seq, 'sentMs', NEW.sent_ms)::text);
    RETURN NULL;
END
$$;
CREATE OR REPLACE TRIGGER probe_row_notify AFTER INSERT ON probe_row
    FOR EACH ROW EXECUTE FUNCTION probe_row_notify();
";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Written {
    seq: i64,
    sent_ms: i64,
}

/// Takes and at once releases the lock when it is free, and reports whether it was.
async fn lock_free(connection: &mut PgConnection, key: i64) -> anyhow::Result<bool> {
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(&mut *connection)
        .await?;
    if acquired {
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(key)
            .execute(&mut *connection)
            .await?;
    }
    Ok(acquired)
}

async fn backend_pid(connection: &mut PgConnection) -> anyhow::Result<i32> {
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection)
        .await?)
}

pub async fn run(
    url: &str,
    password: &str,
    seconds: u64,
    interval_ms: u64,
) -> anyhow::Result<Value> {
    let options = PgConnectOptions::from_str(url)
        .context("parse the database URL")?
        .password(password)
        .application_name("veoveo-qualify-openshell");
    let address = format!("{}:{}", options.get_host(), options.get_port());
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options.clone())
        .await
        .context("connect the query pool")?;
    sqlx::raw_sql(SCHEMA)
        .execute(&pool)
        .await
        .context("create the probe table and trigger")?;
    let server_version: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&pool)
        .await?;
    let tls: Option<bool> =
        sqlx::query_scalar("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            .fetch_optional(&pool)
            .await?;

    // The run ID keys the rows, the notification channel and the advisory lock.
    let run_id = now_ms() as i64;
    let mut holder = options
        .connect()
        .await
        .context("connect the lock session")?;
    let holder_pid = backend_pid(&mut holder).await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(run_id)
        .execute(&mut holder)
        .await
        .context("take the session advisory lock")?;
    let mut contender = pool.acquire().await?;
    let refused_before = !lock_free(&mut contender, run_id).await?;

    let mut listener = PgListener::connect_with(&pool).await?;
    listener.listen(&format!("probe_{run_id}")).await?;

    let count = seconds * 1000 / interval_ms.max(1);
    let writer = {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
            let (mut latency, mut errors, mut first_error) = (Vec::new(), 0u64, None);
            for seq in 0..count {
                interval.tick().await;
                let sent_ms = now_ms();
                let inserted =
                    sqlx::query("INSERT INTO probe_row (run, seq, sent_ms) VALUES ($1, $2, $3)")
                        .bind(run_id)
                        .bind(seq as i64)
                        .bind(sent_ms as i64)
                        .execute(&pool)
                        .await;
                match inserted {
                    Ok(_) => latency.push(now_ms().saturating_sub(sent_ms)),
                    Err(error) => {
                        errors += 1;
                        first_error.get_or_insert(error.to_string());
                    }
                }
            }
            (latency, errors, first_error)
        })
    };

    let (mut latency, mut arrivals, mut out_of_order, mut error) =
        (Vec::new(), Vec::new(), 0u64, None);
    let mut next_seq = 0;
    let deadline = tokio::time::sleep(Duration::from_millis(seconds * 1000 + 10_000));
    tokio::pin!(deadline);
    while (latency.len() as u64) < count {
        tokio::select! {
            received = listener.try_recv() => match received {
                Ok(Some(notification)) => {
                    let now = now_ms();
                    match serde_json::from_str::<Written>(notification.payload()) {
                        Ok(written) => {
                            arrivals.push(now);
                            latency.push(now.saturating_sub(written.sent_ms as u64));
                            if written.seq != next_seq {
                                out_of_order += 1;
                            }
                            next_seq = written.seq + 1;
                        }
                        Err(e) => { error = Some(format!("decode notification: {e}")); break; }
                    }
                }
                Ok(None) => { error = Some("notification connection lost".into()); break; }
                Err(e) => { error = Some(e.to_string()); break; }
            },
            _ = &mut deadline => { error = Some("deadline before all notifications".into()); break; }
        }
    }
    let (query_latency, write_errors, first_write_error) = writer.await?;

    // The lock must still belong to the original session after the stream.
    let lock = async {
        let refused_after = !lock_free(&mut contender, run_id).await?;
        let same_session = backend_pid(&mut holder).await? == holder_pid;
        let released: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
            .bind(run_id)
            .fetch_one(&mut holder)
            .await?;
        let granted_after_release = lock_free(&mut contender, run_id).await?;
        anyhow::Ok(json!({
            "heldThroughStream": refused_before && refused_after && same_session && released && granted_after_release,
            "refusedBeforeStream": refused_before,
            "refusedAfterStream": refused_after,
            "sameSession": same_session,
            "releasedByHolder": released,
            "grantedAfterRelease": granted_after_release,
        }))
    }
    .await
    .unwrap_or_else(|e| json!({"heldThroughStream": false, "error": format!("{e:#}")}));

    let _ = sqlx::query("DELETE FROM probe_row WHERE run = $1")
        .bind(run_id)
        .execute(&mut *contender)
        .await;
    let _ = holder.close().await;
    drop(listener);
    drop(contender);
    pool.close().await;

    Ok(json!({
        "test": "postgres",
        "address": address,
        "serverVersion": server_version,
        "tls": tls,
        "expected": count,
        "notified": latency.len(),
        "outOfOrder": out_of_order,
        "writeErrors": write_errors,
        "firstWriteError": first_write_error,
        "queryLatencyMs": stats::summarize(query_latency),
        "notifyLatencyMs": stats::summarize(latency),
        "maxGapMs": stats::max_gap(&arrivals),
        "advisoryLock": lock,
        "error": error,
    }))
}
