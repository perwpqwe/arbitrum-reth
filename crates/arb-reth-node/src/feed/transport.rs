//! RFC 7692 feed transport. Keep upgrade headers so HTTP backoff is not lost.
use eyre::{Result, ensure};
use http_body_util::Empty;
use hyper::{body::Bytes, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    MaybeTlsStream,
    tungstenite::{
        handshake::derive_accept_key,
        http::{Request, StatusCode},
    },
};

pub(super) type FeedResponse = tokio_tungstenite::tungstenite::http::Response<()>;
pub(super) type FeedSocket = yawc::WebSocket<TokioIo<Upgraded>>;

#[derive(Debug)]
struct Rejected {
    status: StatusCode,
    delay: Duration,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "feed HTTP {}; retry after {}s",
            self.status,
            self.delay.as_secs()
        )
    }
}
impl std::error::Error for Rejected {}

pub(super) fn retry_after(error: &eyre::Report) -> Option<Duration> {
    error.downcast_ref::<Rejected>().map(|error| error.delay)
}

pub(super) async fn connect<S>(
    mut request: Request<()>,
    socket: S,
) -> Result<(FeedSocket, FeedResponse)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = request
        .uri()
        .host()
        .ok_or_else(|| eyre::eyre!("missing feed host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let stream = match request.uri().scheme_str() {
        Some("ws") => MaybeTlsStream::Plain(socket),
        Some("wss") => {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            MaybeTlsStream::Rustls(connector.connect(host.try_into()?, socket).await?)
        }
        _ => eyre::bail!("unsupported feed scheme"),
    };
    let accept = derive_accept_key(request.headers()["sec-websocket-key"].as_bytes());
    request.headers_mut().insert(
        "sec-websocket-extensions",
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover".parse()?,
    );
    *request.uri_mut() = request
        .uri()
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .parse()?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.with_upgrades().await;
    });
    let mut response = sender
        .send_request(request.map(|_| Empty::<Bytes>::new()))
        .await?;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        let fallback = if response.status() == StatusCode::FORBIDDEN {
            3600
        } else {
            60
        };
        let delay = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.parse::<u64>().ok().map(Duration::from_secs).or_else(|| {
                    httpdate::parse_http_date(v)
                        .ok()
                        .map(|time| time.duration_since(SystemTime::now()).unwrap_or_default())
                })
            })
            .unwrap_or(Duration::from_secs(fallback))
            .max(Duration::from_secs(1));
        return Err(Rejected {
            status: response.status(),
            delay,
        }
        .into());
    }
    ensure!(
        response
            .headers()
            .get("sec-websocket-accept")
            .and_then(|v| v.to_str().ok())
            == Some(accept.as_str()),
        "invalid feed WebSocket accept"
    );
    ensure!(
        response
            .headers()
            .get("upgrade")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket")),
        "invalid feed upgrade"
    );
    ensure!(
        response
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v
                .split(',')
                .any(|s| s.trim().eq_ignore_ascii_case("upgrade"))),
        "invalid feed connection header"
    );
    let extensions = response
        .headers()
        .get("sec-websocket-extensions")
        .map(|v| v.to_str())
        .transpose()?
        .map(str::to_owned);
    // We only offer this stateless profile; reject unsupported or unsolicited parameters.
    if let Some(extension) = &extensions {
        let mut parts = extension.split(';').map(str::trim);
        ensure!(
            parts.next() == Some("permessage-deflate")
                && parts.all(|p| matches!(
                    p,
                    "server_no_context_takeover" | "client_no_context_takeover"
                )),
            "unsupported feed compression parameters"
        );
        ensure!(
            extension
                .split(';')
                .any(|p| p.trim() == "server_no_context_takeover"),
            "feed compression requires server_no_context_takeover"
        );
    }
    let stream = TokioIo::new(hyper::upgrade::on(&mut response).await?);
    let websocket = yawc::WebSocket::from_stream_with_extensions(
        stream,
        yawc::Role::Client,
        extensions.as_deref(),
        yawc::Options::default()
            .with_low_latency_compression()
            .with_limits(64 * 1024 * 1024, 64 * 1024 * 1024),
    )?;
    Ok((
        websocket,
        FeedResponse::from_parts(response.into_parts().0, ()),
    ))
}
