//! Probes for policy enforcement, TLS through the inspecting proxy and gRPC-Web.

use serde_json::{Value, json};
use std::time::Duration;

const MCP_VERSION: &str = "2026-07-28";

fn client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()?)
}

fn mcp_body(method: &str, tool: Option<&str>) -> Value {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let params = match tool {
        Some(name) => json!({"name": name, "arguments": {}, "_meta": meta}),
        None => json!({"_meta": meta}),
    };
    json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
}

async fn status(request: reqwest::RequestBuilder) -> Value {
    match request.send().await {
        Ok(response) => json!(response.status().as_u16()),
        Err(error) => json!({"error": error.to_string()}),
    }
}

/// Sends MCP `2026-07-28` requests through an endpoint that OpenShell inspects as MCP.
pub async fn mcp_policy(
    base: &str,
    allowed_tool: &str,
    denied_tool: &str,
) -> anyhow::Result<Value> {
    let client = client()?;
    let url = format!("{base}/mcp");
    let call = |method: &str, tool: Option<&str>| {
        let mut request = client
            .post(&url)
            .header("MCP-Protocol-Version", MCP_VERSION)
            .header("Mcp-Method", method)
            .json(&mcp_body(method, tool));
        if let Some(tool) = tool {
            request = request.header("Mcp-Name", tool);
        }
        request
    };
    let missing_method_header = client
        .post(&url)
        .header("MCP-Protocol-Version", MCP_VERSION)
        .json(&mcp_body("tools/list", None));
    Ok(json!({
        "test": "mcp_policy",
        "toolsList": status(call("tools/list", None)).await,
        "serverDiscover": status(call("server/discover", None)).await,
        "allowedTool": status(call("tools/call", Some(allowed_tool))).await,
        "deniedTool": status(call("tools/call", Some(denied_tool))).await,
        "missingMethodHeader": status(missing_method_header).await,
    }))
}

/// Fetches an HTTPS URL with the default rustls-based client.
pub async fn https(url: &str) -> anyhow::Result<Value> {
    let outcome = match client()?.get(url).send().await {
        Ok(response) => json!({"status": response.status().as_u16()}),
        Err(error) => json!({"error": format!("{error:?}").chars().take(400).collect::<String>()}),
    };
    Ok(json!({"test": "https", "url": url, "outcome": outcome}))
}

/// Calls a unary gRPC method over gRPC-Web with an empty request message.
pub async fn grpc_web(base: &str, method_path: &str) -> anyhow::Result<Value> {
    let empty_message = vec![0u8, 0, 0, 0, 0];
    let response = reqwest::Client::builder()
        .http1_only()
        .connect_timeout(Duration::from_secs(10))
        .build()?
        .post(format!("{base}{method_path}"))
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(empty_message)
        .send()
        .await;
    Ok(match response {
        Ok(response) => {
            let status = response.status().as_u16();
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            let body = response.bytes().await.unwrap_or_default();
            let trailer_ok = String::from_utf8_lossy(&body).contains("grpc-status:0");
            json!({"test": "grpc_web", "status": status, "contentType": content_type, "grpcStatusOk": trailer_ok, "bodyBytes": body.len()})
        }
        Err(error) => json!({"test": "grpc_web", "error": error.to_string()}),
    })
}
