//! Transport probe that runs inside OpenShell sandboxes and on the host.

use clap::{Parser, Subcommand};
use veoveo_qualify_openshell::{client, grpc, postgres, probes, server};

#[derive(Parser)]
#[command(name = "probe")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the HTTP probe routes and the gRPC probe service.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8080")]
        http: std::net::SocketAddr,
        #[arg(long, default_value = "127.0.0.1:50051")]
        grpc: std::net::SocketAddr,
    },
    /// One-shot HTTP checks: health, MCP POST, form token, bearer and Basic authorization, 8 MiB body.
    Http {
        #[arg(long)]
        base: String,
        #[arg(long, default_value = "probe-bearer-token")]
        bearer: String,
    },
    /// Hold one or more SSE streams and measure delivery lateness.
    Sse {
        #[arg(long)]
        base: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
        #[arg(long, default_value_t = 1)]
        streams: usize,
    },
    /// Hold a length-framed binary stream and measure delivery lateness.
    Frames {
        #[arg(long)]
        base: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long, default_value_t = 100)]
        interval_ms: u64,
        #[arg(long, default_value_t = 65536)]
        frame_bytes: usize,
    },
    /// Download a large deterministic body and verify it.
    Big {
        #[arg(long)]
        base: String,
        #[arg(long, default_value_t = 1 << 30)]
        bytes: u64,
    },
    /// Hold a WebSocket echo session and measure round trips.
    Ws {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Hold a gRPC bidirectional stream and a server stream over HTTP/2.
    Grpc {
        #[arg(long)]
        url: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Run PostgreSQL queries, hold a session advisory lock and follow writes through
    /// LISTEN/NOTIFY.
    Postgres {
        /// A `postgres://` URL without a password.
        #[arg(long, env = "VEOVEO_DATABASE_URL")]
        url: String,
        #[arg(long, env = "VEOVEO_DATABASE_PASSWORD", hide_env_values = true)]
        password: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long, default_value_t = 1000)]
        interval_ms: u64,
    },
    /// Send MCP 2026-07-28 requests through an MCP-inspected endpoint.
    McpPolicy {
        #[arg(long)]
        base: String,
        #[arg(long, default_value = "allowed_tool")]
        allowed_tool: String,
        #[arg(long, default_value = "forbidden_tool")]
        denied_tool: String,
    },
    /// Fetch an HTTPS URL with the rustls-based client.
    Https {
        #[arg(long)]
        url: String,
    },
    /// Call a unary gRPC method over gRPC-Web.
    GrpcWeb {
        #[arg(long)]
        base: String,
        #[arg(long)]
        method: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let report = match Cli::parse().command {
        Command::Serve { http, grpc } => {
            server::serve(http, grpc).await?;
            return Ok(());
        }
        Command::Http { base, bearer } => client::http(&base, &bearer).await?,
        Command::Sse {
            base,
            seconds,
            interval_ms,
            streams,
        } => client::sse(&base, seconds, interval_ms, streams).await?,
        Command::Frames {
            base,
            seconds,
            interval_ms,
            frame_bytes,
        } => client::frames(&base, seconds, interval_ms, frame_bytes).await?,
        Command::Big { base, bytes } => client::big(&base, bytes).await?,
        Command::Ws {
            url,
            seconds,
            interval_ms,
        } => client::ws(&url, seconds, interval_ms).await?,
        Command::Grpc {
            url,
            seconds,
            interval_ms,
        } => grpc::client(&url, seconds, interval_ms).await?,
        Command::Postgres {
            url,
            password,
            seconds,
            interval_ms,
        } => postgres::run(&url, &password, seconds, interval_ms).await?,
        Command::McpPolicy {
            base,
            allowed_tool,
            denied_tool,
        } => probes::mcp_policy(&base, &allowed_tool, &denied_tool).await?,
        Command::Https { url } => probes::https(&url).await?,
        Command::GrpcWeb { base, method } => probes::grpc_web(&base, &method).await?,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
