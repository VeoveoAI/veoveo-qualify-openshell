//! Verified sandbox HTTPS ingress to the deterministic native service fixture.

use anyhow::{Context, Result, ensure};
use reqwest::{Client, Response, StatusCode, Url};
use serde_json::{Value, json};
use std::time::Duration;

/// Accept only the built-in, single-label HTTPS service origin under qualification.
pub fn origin(value: &str) -> Result<Url> {
    let url = Url::parse(value)?;
    let label = url
        .host_str()
        .and_then(|host| host.strip_suffix(".openshell.localhost"))
        .context("service origin must use openshell.localhost")?;
    ensure!(
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.port_or_known_default().is_some_and(|port| port != 0)
            && !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "service origin must be an unmodified one-label HTTPS origin"
    );
    Ok(url)
}

fn client() -> Result<Client> {
    // Use the sandbox's provisioned platform roots. Keep SNI and hostname checks;
    // never resolve overrides or caller-provided roots for this positive path.
    Ok(Client::builder()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()?)
}

async fn body(mut response: Response) -> Result<(StatusCode, Vec<u8>)> {
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 16 * 1024,
            "ingress body exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, bytes))
}

async fn rpc(client: &Client, url: Url, request: Value) -> Result<Value> {
    let (status, bytes) = body(
        client
            .post(url)
            .bearer_auth("fixture-app-token")
            .header("MCP-Protocol-Version", "2025-11-25")
            .json(&request)
            .send()
            .await?,
    )
    .await?;
    ensure!(status == StatusCode::OK, "MCP request answered {status}");
    let response: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        response["jsonrpc"] == "2.0"
            && response["id"] == request["id"]
            && response["error"].is_null()
            && response["result"].is_object(),
        "invalid MCP response"
    );
    Ok(response["result"].clone())
}

async fn refused_destination(request: reqwest::RequestBuilder) -> Result<Value> {
    match request.send().await {
        Ok(response) => {
            let (status, _) = body(response).await?;
            ensure!(
                status == StatusCode::FORBIDDEN,
                "denied destination answered {status}"
            );
            Ok(json!({"status": status.as_u16()}))
        }
        Err(error) => {
            ensure!(
                !error.is_timeout(),
                "timeout does not establish destination refusal"
            );
            ensure!(
                error.is_connect() || error.is_request(),
                "unexpected destination failure"
            );
            Ok(json!({"transportRefused": true, "connectError": error.is_connect()}))
        }
    }
}

/// Run once in a fresh process/connection after each exposure lifecycle transition.
pub async fn run(base: &str, deleted: bool) -> Result<Value> {
    let base = origin(base)?;
    let client = client()?;
    let health_url = base.join("healthz")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let (health, bytes) = loop {
        let result = body(client.get(health_url.clone()).send().await?).await?;
        if !deleted
            && matches!(
                result.0,
                StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE
            )
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        break result;
    };
    if deleted {
        ensure!(
            health == StatusCode::NOT_FOUND,
            "deleted exposure answered {health}"
        );
        return Ok(json!({"phase":"deleted", "healthStatus":health.as_u16()}));
    }
    ensure!(
        health == StatusCode::OK && bytes == b"ok",
        "service health failed: {health}"
    );
    let mcp = base.join("first-mcp")?;
    let initialized = rpc(
        &client,
        mcp.clone(),
        json!({"jsonrpc":"2.0","id":1,
        "method":"initialize", "params":{"protocolVersion":"2025-11-25",
        "capabilities":{},"clientInfo":{"name":"service-ingress","version":"0.1.0"}}}),
    )
    .await?;
    ensure!(
        initialized["protocolVersion"] == "2025-11-25"
            && initialized["serverInfo"]["name"] == "veoveo-first-mcp",
        "MCP initialization failed"
    );
    let (notification, _) = body(
        client
            .post(mcp.clone())
            .bearer_auth("fixture-app-token")
            .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .await?,
    )
    .await?;
    ensure!(
        notification == StatusCode::ACCEPTED,
        "MCP initialization notification failed"
    );
    let tools = rpc(
        &client,
        mcp.clone(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await?;
    ensure!(tools["tools"][0]["name"] == "echo", "MCP discovery failed");
    let call = json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"echo","arguments":{"text":"native-service-ingress"}}});
    let echoed = rpc(&client, mcp.clone(), call.clone()).await?;
    ensure!(
        echoed["content"][0]["text"] == "native-service-ingress" && echoed["isError"] == false,
        "MCP echo failed"
    );
    let (unauthenticated, _) = body(client.post(mcp).json(&call).send().await?).await?;
    ensure!(
        unauthenticated == StatusCode::UNAUTHORIZED,
        "application did not require credentials"
    );
    let (denied_path, _) = body(client.get(base.join("denied")?).send().await?).await?;
    ensure!(
        denied_path == StatusCode::FORBIDDEN,
        "unlisted path answered {denied_path}"
    );
    let host = base.host_str().context("service host")?;
    let port = base.port_or_known_default().context("service port")?;
    let other_port = port.checked_add(1).unwrap_or(port - 1);
    let mut authorities = Vec::new();
    for authority in [
        format!("host.openshell.internal:{port}"),
        format!("{host}:{other_port}"),
    ] {
        // Negative only: the URL, TLS SNI and CONNECT target stay unchanged.
        let (status, bytes) = body(
            client
                .get(base.join("healthz")?)
                .header(reqwest::header::HOST, authority)
                .send()
                .await?,
        )
        .await?;
        ensure!(
            status == StatusCode::FORBIDDEN
                && serde_json::from_slice::<Value>(&bytes)?["error"]
                    == "request_authority_mismatch",
            "mismatched request authority was not explicitly rejected"
        );
        authorities.push(status.as_u16());
    }
    let mut wrong_port = base.clone();
    wrong_port
        .set_port(Some(other_port))
        .map_err(|()| anyhow::anyhow!("invalid negative port"))?;
    let wrong_port = refused_destination(client.get(wrong_port.join("healthz")?)).await?;
    let mut wrong_name = base.clone();
    wrong_name.set_host(Some("unadmitted-service.openshell.localhost"))?;
    let wrong_name = refused_destination(client.get(wrong_name.join("healthz")?)).await?;
    Ok(json!({"phase":"available", "healthStatus":health.as_u16(),
        "initialize":true,"initializedStatus":notification.as_u16(),"discovery":true,"echo":true,
        "unauthenticatedStatus":unauthenticated.as_u16(),"deniedPathStatus":denied_path.as_u16(),
        "authorityMismatchStatuses":authorities,"wrongPort":wrong_port,"wrongName":wrong_name}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_origin_requires_native_https_without_authority_workarounds() {
        assert!(
            origin("https://vv-qual-abc--vv-qual-abc-s--http.openshell.localhost:17670/").is_ok()
        );
        for value in [
            "http://service.openshell.localhost:17670",
            "https://host.openshell.internal:17670",
            "https://nested.service.openshell.localhost:17670",
            "https://openshell.localhost:17670",
            "https://service.openshell.localhost:0",
            "https://service.openshell.localhost/path",
            "https://user@service.openshell.localhost",
            "https://service.openshell.localhost/?x=1",
            "https://service.openshell.localhost/#fragment",
            "https://-service.openshell.localhost",
        ] {
            assert!(
                origin(value).is_err(),
                "accepted invalid ingress origin: {value}"
            );
        }
    }
}
