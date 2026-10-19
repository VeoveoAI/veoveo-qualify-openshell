//! Read-only direct native ForwardTcp proof using an existing restricted identity.
use anyhow::{Context, Result, bail, ensure};
use openshell_sdk::{OpenShellClient, raw::proto as p};
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;

#[derive(clap::Args)]
pub struct Options {
    /// Existing state/openshell/<identity>.json; never a new identity or grant.
    #[arg(long)]
    pub identity: String,
    #[arg(long)]
    allowed_workspace: String,
    #[arg(long)]
    allowed_sandbox: String,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    allowed_port: u16,
    #[arg(long)]
    denied_workspace: String,
    #[arg(long)]
    denied_sandbox: String,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
    denied_port: u16,
    /// Logical HTTP readiness URL, preserving Host through the native TCP stream.
    #[arg(long)]
    ready_url: reqwest::Url,
}

impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.identity.is_empty()
                && self
                    .identity
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "identity must be one filename component of letters, digits, underscores or hyphens"
        );
        ensure!(
            self.allowed_workspace != self.denied_workspace,
            "allowed and denied workspaces must differ"
        );
        ensure!(
            self.ready_url.scheme() == "http"
                && self.ready_url.has_host()
                && self.ready_url.username().is_empty()
                && self.ready_url.password().is_none()
                && self.ready_url.query().is_none()
                && self.ready_url.fragment().is_none()
                && self.ready_url.port_or_known_default() == Some(self.allowed_port),
            "ready-url must be an HTTP URL without credentials, query or fragment and match allowed-port"
        );
        Ok(())
    }

    fn readiness(&self) -> Vec<u8> {
        // URL parsing and validation own the authority; no DNS or Host rewrite occurs.
        let authority = self
            .ready_url
            .as_str()
            .strip_prefix("http://")
            .unwrap()
            .split('/')
            .next()
            .unwrap();
        format!(
            "GET {} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n",
            self.ready_url.path()
        )
        .into_bytes()
    }
}

pub struct Target {
    pub workspace: String,
    pub sandbox: String,
    pub port: u16,
}

type Opened = (
    tokio::sync::mpsc::Sender<p::TcpForwardFrame>,
    tonic::Streaming<p::TcpForwardFrame>,
);

async fn open(client: &OpenShellClient, target: &Target) -> Result<Opened> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(p::TcpForwardFrame {
        payload: Some(p::tcp_forward_frame::Payload::Init(p::TcpForwardInit {
            sandbox: target.sandbox.clone(),
            workspace: target.workspace.clone(),
            target: Some(p::tcp_forward_init::Target::Tcp(p::TcpRelayTarget {
                host: "127.0.0.1".into(),
                port: u32::from(target.port),
            })),
            ..Default::default()
        })),
    })
    .await?;
    let stream = client
        .raw_grpc_fresh()
        .await?
        .forward_tcp(ReceiverStream::new(rx))
        .await?
        .into_inner();
    Ok((tx, stream))
}

/// The existing first-path request helper, with explicit native target coordinates.
pub async fn request(client: &OpenShellClient, target: &Target, bytes: Vec<u8>) -> Result<Vec<u8>> {
    let (tx, mut stream) = open(client, target).await?;
    tx.send(p::TcpForwardFrame {
        payload: Some(p::tcp_forward_frame::Payload::Data(bytes)),
    })
    .await?;
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(frame) = stream.message().await? {
            if let Some(p::tcp_forward_frame::Payload::Data(data)) = frame.payload {
                ensure!(
                    output.len() + data.len() <= 1024 * 1024,
                    "forward response exceeded limit"
                );
                output.extend(data);
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    drop(tx);
    Ok(output)
}

pub async fn run(client: &OpenShellClient, options: &Options) -> Result<()> {
    options.validate()?;
    let allowed = Target {
        workspace: options.allowed_workspace.clone(),
        sandbox: options.allowed_sandbox.clone(),
        port: options.allowed_port,
    };
    let denied = Target {
        workspace: options.denied_workspace.clone(),
        sandbox: options.denied_sandbox.clone(),
        port: options.denied_port,
    };
    let response = request(client, &allowed, options.readiness())
        .await
        .context("allowed ForwardTcp readiness request failed")?;
    ensure!(
        response.starts_with(b"HTTP/1.1 200 ") || response.starts_with(b"HTTP/1.0 200 "),
        "allowed ForwardTcp readiness did not return HTTP 200"
    );
    // Init only: no HTTP bytes, lookup, execution or mutation at the denied target.
    match open(client, &denied).await {
        Ok(_) => bail!("denied ForwardTcp target was admitted"),
        Err(error) => ensure!(
            error
                .downcast_ref::<tonic::Status>()
                .is_some_and(|status| status.code() == tonic::Code::NotFound),
            "denied ForwardTcp did not return NotFound (gRPC code: {:?})",
            error
                .downcast_ref::<tonic::Status>()
                .map(tonic::Status::code)
        ),
    }
    println!(
        "Direct ForwardTcp readiness returned HTTP 200; distinct-workspace target returned NotFound. Target existence must be confirmed independently."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::Infallible,
        sync::Arc,
        task::{Context as TaskContext, Poll},
    };
    use tokio::sync::{Mutex, mpsc};
    use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
    use tonic::codegen::{Body, BoxFuture, Service, StdError, http};

    #[derive(Clone)]
    struct Gateway {
        denied: Option<tonic::Code>,
        status: u16,
        calls: Arc<Mutex<Vec<p::TcpForwardInit>>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    // One real gRPC route, rather than stubs for the gateway's unrelated methods.
    impl tonic::server::NamedService for Gateway {
        const NAME: &'static str = "openshell.v1.OpenShell";
    }

    impl<B> Service<http::Request<B>> for Gateway
    where
        B: Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            assert_eq!(request.uri().path(), "/openshell.v1.OpenShell/ForwardTcp");
            let rpc = self.clone();
            Box::pin(async move {
                Ok(tonic::server::Grpc::new(tonic_prost::ProstCodec::default())
                    .streaming(rpc, request)
                    .await)
            })
        }
    }

    impl tonic::server::StreamingService<p::TcpForwardFrame> for Gateway {
        type Response = p::TcpForwardFrame;
        type ResponseStream = ReceiverStream<Result<Self::Response, tonic::Status>>;
        type Future = BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;

        fn call(
            &mut self,
            request: tonic::Request<tonic::Streaming<p::TcpForwardFrame>>,
        ) -> Self::Future {
            let state = self.clone();
            Box::pin(async move {
                assert_eq!(
                    request.metadata().get("authorization").unwrap(),
                    "Bearer fixture-token"
                );
                let mut inbound = request.into_inner();
                let Some(p::tcp_forward_frame::Payload::Init(init)) =
                    inbound.message().await?.unwrap().payload
                else {
                    panic!("first frame must be init");
                };
                state.calls.lock().await.push(init.clone());
                let (tx, rx) = mpsc::channel(1);
                if init.workspace == "vv-control" {
                    if let Some(code) = state.denied {
                        return Err(tonic::Status::new(code, "fixture refusal"));
                    }
                } else {
                    // ForwardTcp admits Init and returns response headers before
                    // the client sends Data. Waiting for Data here deadlocks open().
                    tokio::spawn(async move {
                        let Some(p::tcp_forward_frame::Payload::Data(bytes)) =
                            inbound.message().await.unwrap().unwrap().payload
                        else {
                            panic!("allowed target must receive one readiness request");
                        };
                        state.requests.lock().await.push(bytes);
                        let _ = tx.send(Ok(p::TcpForwardFrame {
                            payload: Some(p::tcp_forward_frame::Payload::Data(
                                format!("HTTP/1.1 {} Fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", state.status).into_bytes()
                            )),
                        })).await;
                    });
                }
                Ok(tonic::Response::new(ReceiverStream::new(rx)))
            })
        }
    }

    struct Serving(tokio::task::JoinHandle<()>);
    impl Drop for Serving {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    async fn serve(
        denied: Option<tonic::Code>,
        status: u16,
    ) -> Result<(OpenShellClient, Gateway, Serving)> {
        let gateway = Gateway {
            denied,
            status,
            calls: Arc::default(),
            requests: Arc::default(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mut config =
            openshell_sdk::ClientConfig::new(format!("http://{}", listener.local_addr()?));
        config.auth = Some(openshell_sdk::AuthConfig::oidc("fixture-token"));
        let service = gateway.clone();
        let serving = Serving(tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        }));
        Ok((OpenShellClient::connect(config).await?, gateway, serving))
    }

    fn options() -> Options {
        Options {
            identity: "forwarder".into(),
            allowed_workspace: "vv-services".into(),
            allowed_sandbox: "time".into(),
            allowed_port: 8800,
            denied_workspace: "vv-control".into(),
            denied_sandbox: "hub".into(),
            denied_port: 8080,
            ready_url: "http://time.internal:8800/readyz".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn direct_forward_uses_only_explicit_init_targets_and_one_readiness_get() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let (client, gateway, _serving) = serve(Some(tonic::Code::NotFound), 200).await?;
            run(&client, &options()).await?;
            let calls = gateway.calls.lock().await;
            assert_eq!(calls.len(), 2);
            for (init, workspace, sandbox, port) in [
                (&calls[0], "vv-services", "time", 8800),
                (&calls[1], "vv-control", "hub", 8080),
            ] {
                assert_eq!((&*init.workspace, &*init.sandbox), (workspace, sandbox));
                assert!(init.authorization_token.is_empty());
                let Some(p::tcp_forward_init::Target::Tcp(target)) = &init.target else {
                    panic!("TCP target required");
                };
                assert_eq!((&*target.host, target.port), ("127.0.0.1", port));
            }
            assert_eq!(
            *gateway.requests.lock().await,
            [
                b"GET /readyz HTTP/1.1\r\nHost: time.internal:8800\r\nConnection: close\r\n\r\n"
                    .to_vec()
            ]
        );
            Ok(())
        })
        .await
        .context("direct ForwardTcp fixture exceeded ten seconds")?
    }

    #[tokio::test]
    async fn unrelated_refusals_or_admitted_denied_target_never_pass() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            for code in [
                Some(tonic::Code::PermissionDenied),
                Some(tonic::Code::Unauthenticated),
                Some(tonic::Code::Unavailable),
                None,
            ] {
                let (client, _, _serving) = serve(code, 200).await?;
                assert!(run(&client, &options()).await.is_err());
            }
            let (client, gateway, _serving) = serve(Some(tonic::Code::NotFound), 503).await?;
            assert!(run(&client, &options()).await.is_err());
            assert_eq!(gateway.calls.lock().await.len(), 1);
            Ok(())
        })
        .await
        .context("ForwardTcp refusal fixtures exceeded ten seconds")?
    }

    #[test]
    fn invalid_inputs_are_rejected_before_credentials_or_network() {
        for identity in ["", "../controller", "forwarder/other", "forwarder\n"] {
            let mut args = options();
            args.identity = identity.into();
            assert!(args.validate().is_err());
        }
        for url in [
            "https://time.internal:8800/readyz",
            "http://secret@time.internal:8800/readyz",
            "http://time.internal:8800/readyz?secret=x",
            "http://time.internal:8800/readyz#x",
            "http://time.internal:8080/readyz",
        ] {
            let mut args = options();
            args.ready_url = url.parse().unwrap();
            assert!(args.validate().is_err());
        }
        let mut args = options();
        args.denied_workspace = args.allowed_workspace.clone();
        assert!(args.validate().is_err());
    }
}
