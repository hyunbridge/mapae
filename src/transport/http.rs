use anyhow::Context;
use hyper::server::conn::http1::Builder as Http1Builder;
use serde::Serialize;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{error, warn};
use warp::http::header::CONTENT_TYPE;
use warp::http::HeaderValue;
use warp::http::StatusCode;
use warp::{Filter, Reply};

use crate::auth::{AuthError, Service};
use crate::config::{allows_any_cors_origin, Settings};
use crate::metrics::METRICS;
use crate::runtime::RuntimeState;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    storage: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    detail: String,
}

const HTTP_READ_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const ERROR_INTERNAL_SERVER: &str = "Internal server error";
const ERROR_METHOD_NOT_ALLOWED: &str = "Method not allowed";
const ERROR_NOT_FOUND: &str = "Not found";
const ERROR_SERVICE_UNAVAILABLE: &str = "Service unavailable";
const ERROR_INVALID_AUTH_ID: &str = "Invalid auth_id";
const CORS_ALLOWED_HEADERS: [&str; 2] = ["authorization", "content-type"];
const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// 프론트엔드 및 백엔드 클라이언트가 접근하는 HTTP API 데몬을 실행합니다.
///
/// 인증 세션 생성, 상태 폴링 검사(`/auth/check`), 보안 토큰 발급,
/// 그리고 JWKS 엔드포인트를 `warp` 웹 프레임워크를 기반으로 제공합니다.
pub async fn run(
    config: Arc<Settings>,
    auth_service: Arc<Service>,
    runtime_state: Arc<RuntimeState>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let cors_origins: Vec<String> = config.cors_allow_origins.clone();
    let cors = build_cors(&cors_origins);
    if allows_any_cors_origin(&cors_origins) {
        warn!("HTTP CORS allows any origin; set CORS_ALLOW_ORIGINS for production deployments");
    }
    let auth_filter = with_auth(auth_service);
    let runtime_filter = with_runtime_state(runtime_state);

    let health = warp::path("health")
        .and(warp::path::end())
        .and(warp::get())
        .and(auth_filter.clone())
        .and_then(health_handler);

    let live = warp::path("live")
        .and(warp::path::end())
        .and(warp::get())
        .and_then(live_handler);

    let ready = warp::path("ready")
        .and(warp::path::end())
        .and(warp::get())
        .and(auth_filter.clone())
        .and(runtime_filter)
        .and_then(ready_handler);

    let metrics = warp::path("metrics")
        .and(warp::path::end())
        .and(warp::get())
        .and_then(metrics_handler);

    let auth_init = warp::path("auth")
        .and(warp::path("init"))
        .and(warp::path::end())
        .and(warp::post())
        .and(auth_filter.clone())
        .and_then(auth_init_handler);

    let auth_check = warp::path("auth")
        .and(warp::path("check"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(warp::get())
        .and(auth_filter.clone())
        .and_then(auth_check_handler);

    let auth_check_signed = warp::path("auth")
        .and(warp::path("check-signed"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(warp::get())
        .and(auth_filter.clone())
        .and_then(auth_check_signed_handler);

    let jwks = warp::path(".well-known")
        .and(warp::path("jwks.json"))
        .and(warp::path::end())
        .and(warp::get())
        .and(auth_filter)
        .and_then(jwks_handler);

    let routes = health
        .or(live)
        .or(ready)
        .or(metrics)
        .or(auth_init)
        .or(auth_check)
        .or(auth_check_signed)
        .or(jwks)
        .recover(handle_rejection)
        .with(cors)
        .with(warp::log("mapae::http"));

    let addr: std::net::SocketAddr = format!("{}:{}", config.http_host, config.http_port)
        .parse()
        .context("invalid HTTP addr")?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("HTTP bind error")?;

    let connection_limit = Arc::new(Semaphore::new(config.http_max_connections));
    let mut connections = JoinSet::new();

    tracing::info!("HTTP server listening on {}", addr);
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::info!("HTTP shutdown requested");
                    break;
                }
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(err)) = result {
                    warn!("HTTP connection task failed: {}", err);
                }
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(conn) => conn,
                    Err(err) => {
                        warn!("HTTP accept error: {}", err);
                        continue;
                    }
                };

                let Ok(permit) = connection_limit.clone().try_acquire_owned() else {
                    METRICS.inc_http_connection_limit_rejection();
                    warn!(
                        "Rejected HTTP connection from {}: connection limit reached",
                        peer
                    );
                    connections.spawn(reject_http_connection(stream));
                    continue;
                };

                if let Err(err) = stream.set_nodelay(true) {
                    warn!("HTTP set_nodelay failed for {}: {}", peer, err);
                }

                let routes = routes.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let mut io = tokio_io_timeout::TimeoutStream::new(stream);
                    io.set_read_timeout(Some(HTTP_READ_TIMEOUT));
                    io.set_write_timeout(Some(HTTP_WRITE_TIMEOUT));

                    let io = hyper_util::rt::TokioIo::new(Box::pin(io));
                    let service = hyper_util::service::TowerToHyperService::new(warp::service(routes));

                    let mut builder = Http1Builder::new();
                    builder
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(Some(HTTP_READ_HEADER_TIMEOUT))
                        .keep_alive(true);

                    if let Err(err) = builder
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        warn!("HTTP connection error from {}: {}", peer, err);
                    }
                });
            }
        }
    }

    while let Some(result) = connections.join_next().await {
        if let Err(err) = result {
            warn!("HTTP connection task failed: {}", err);
        }
    }

    Ok(())
}

async fn reject_http_connection(mut stream: TcpStream) {
    let body = serde_json::to_vec(&error_response(ERROR_SERVICE_UNAVAILABLE))
        .unwrap_or_else(|_| br#"{"detail":"Service unavailable"}"#.to_vec());
    let mut response = format!(
        "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(&body);
    if let Err(err) = stream.write_all(&response).await {
        warn!("HTTP reject write failed: {}", err);
    }
    if let Err(err) = stream.shutdown().await {
        warn!("HTTP reject shutdown failed: {}", err);
    }
}

async fn handle_rejection(err: warp::Rejection) -> Result<impl Reply, Infallible> {
    let (status, detail) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, ERROR_NOT_FOUND)
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        (StatusCode::METHOD_NOT_ALLOWED, ERROR_METHOD_NOT_ALLOWED)
    } else {
        error!("unhandled HTTP rejection: {:?}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, ERROR_INTERNAL_SERVER)
    };

    Ok(warp::reply::with_status(
        warp::reply::json(&error_response(detail)),
        status,
    ))
}

fn build_cors(origins: &[String]) -> warp::filters::cors::Cors {
    let builder = warp::cors()
        .allow_methods(vec!["GET", "POST", "OPTIONS"])
        .allow_headers(CORS_ALLOWED_HEADERS);

    if allows_any_cors_origin(origins) {
        builder.allow_any_origin().build()
    } else {
        builder
            .allow_origins(origins.iter().map(|origin| origin.as_str()))
            .build()
    }
}

fn with_auth(
    auth: Arc<Service>,
) -> impl Filter<Extract = (Arc<Service>,), Error = Infallible> + Clone {
    warp::any().map(move || auth.clone())
}

fn with_runtime_state(
    state: Arc<RuntimeState>,
) -> impl Filter<Extract = (Arc<RuntimeState>,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

async fn health_handler(auth: Arc<Service>) -> Result<impl Reply, Infallible> {
    match auth.ping().await {
        Ok(()) => Ok(warp::reply::with_status(
            warp::reply::json(&HealthResponse {
                status: "ok".to_string(),
                storage: "up".to_string(),
            }),
            StatusCode::OK,
        )),
        Err(_) => Ok(warp::reply::with_status(
            warp::reply::json(&HealthResponse {
                status: "unhealthy".to_string(),
                storage: "down".to_string(),
            }),
            StatusCode::SERVICE_UNAVAILABLE,
        )),
    }
}

async fn live_handler() -> Result<impl Reply, Infallible> {
    Ok(warp::reply::with_status(
        warp::reply::json(&StatusResponse {
            status: "ok".to_string(),
        }),
        StatusCode::OK,
    ))
}

async fn ready_handler(
    auth: Arc<Service>,
    runtime_state: Arc<RuntimeState>,
) -> Result<impl Reply, Infallible> {
    let storage_up = auth.ping().await.is_ok();
    let (status, body) = readiness_response(storage_up, runtime_state.is_draining());

    Ok(warp::reply::with_status(warp::reply::json(&body), status))
}

async fn metrics_handler() -> Result<impl Reply, Infallible> {
    Ok(response_with_text_body(
        StatusCode::OK,
        METRICS.render_prometheus().into_bytes(),
        PROMETHEUS_CONTENT_TYPE,
    ))
}

async fn auth_init_handler(auth: Arc<Service>) -> Result<impl Reply, Infallible> {
    METRICS.inc_auth_init();
    match auth.init_auth().await {
        Ok(resp) => Ok(warp::reply::with_status(
            warp::reply::json(&resp),
            StatusCode::OK,
        )),
        Err(e) => {
            error!("auth init error: {}", e);
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response(ERROR_INTERNAL_SERVER)),
                StatusCode::INTERNAL_SERVER_ERROR,
            ))
        }
    }
}

async fn auth_check_handler(auth_id: String, auth: Arc<Service>) -> Result<impl Reply, Infallible> {
    METRICS.inc_auth_check();
    let auth_id = auth_id.trim();
    if auth_id.is_empty() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&error_response(ERROR_INVALID_AUTH_ID)),
            StatusCode::BAD_REQUEST,
        ));
    }

    match auth.check_auth(auth_id).await {
        Ok(resp) => Ok(warp::reply::with_status(
            warp::reply::json(&resp),
            StatusCode::OK,
        )),
        Err(e) => {
            if matches!(e, AuthError::InvalidAuthId) {
                Ok(warp::reply::with_status(
                    warp::reply::json(&error_response(ERROR_INVALID_AUTH_ID)),
                    StatusCode::BAD_REQUEST,
                ))
            } else {
                error!("auth check error: {}", e);
                Ok(warp::reply::with_status(
                    warp::reply::json(&error_response(ERROR_INTERNAL_SERVER)),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        }
    }
}

async fn auth_check_signed_handler(
    auth_id: String,
    auth: Arc<Service>,
) -> Result<impl Reply, Infallible> {
    METRICS.inc_auth_check_signed();
    let auth_id = auth_id.trim();
    if auth_id.is_empty() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&error_response(ERROR_INVALID_AUTH_ID)),
            StatusCode::BAD_REQUEST,
        ));
    }

    match auth.check_signed(auth_id).await {
        Ok(resp) => Ok(warp::reply::with_status(
            warp::reply::json(&resp),
            StatusCode::OK,
        )),
        Err(e) => {
            if matches!(e, AuthError::InvalidAuthId) {
                Ok(warp::reply::with_status(
                    warp::reply::json(&error_response(ERROR_INVALID_AUTH_ID)),
                    StatusCode::BAD_REQUEST,
                ))
            } else if matches!(e, AuthError::JwksUnavailable) {
                Ok(warp::reply::with_status(
                    warp::reply::json(&error_response("JWT signer unavailable")),
                    StatusCode::SERVICE_UNAVAILABLE,
                ))
            } else {
                error!("auth result error: {}", e);
                Ok(warp::reply::with_status(
                    warp::reply::json(&error_response(ERROR_INTERNAL_SERVER)),
                    StatusCode::INTERNAL_SERVER_ERROR,
                ))
            }
        }
    }
}

async fn jwks_handler(auth: Arc<Service>) -> Result<impl Reply, Infallible> {
    match auth.jwks() {
        Ok(data) => {
            let resp = response_with_json_body(StatusCode::OK, data);
            Ok(resp)
        }
        Err(e) => {
            error!("jwks error: {}", e);
            let json = serde_json::to_vec(&error_response("JWKS unavailable"))
                .unwrap_or_else(|_| b"{\"detail\":\"JWKS unavailable\"}".to_vec());
            Ok(response_with_json_body(
                StatusCode::SERVICE_UNAVAILABLE,
                json,
            ))
        }
    }
}

fn response_with_json_body(status: StatusCode, body: Vec<u8>) -> warp::http::Response<Vec<u8>> {
    response_with_text_body(status, body, "application/json")
}

fn response_with_text_body(
    status: StatusCode,
    body: Vec<u8>,
    content_type: &'static str,
) -> warp::http::Response<Vec<u8>> {
    let mut response = warp::http::Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

fn readiness_response(storage_up: bool, draining: bool) -> (StatusCode, HealthResponse) {
    if draining {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            HealthResponse {
                status: "draining".to_string(),
                storage: if storage_up { "up" } else { "down" }.to_string(),
            },
        );
    }

    if storage_up {
        (
            StatusCode::OK,
            HealthResponse {
                status: "ok".to_string(),
                storage: "up".to_string(),
            },
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            HealthResponse {
                status: "unhealthy".to_string(),
                storage: "down".to_string(),
            },
        )
    }
}

fn error_response(detail: &str) -> ErrorResponse {
    ErrorResponse {
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{build_cors, readiness_response, response_with_text_body, PROMETHEUS_CONTENT_TYPE};
    use crate::config::allows_any_cors_origin;
    use warp::http::header::CONTENT_TYPE;
    use warp::http::StatusCode;

    #[test]
    fn cors_origin_wildcard_is_explicit() {
        assert!(allows_any_cors_origin(&["*".to_string()]));
        assert!(allows_any_cors_origin(&[" * ".to_string()]));
        assert!(!allows_any_cors_origin(
            &["https://example.com".to_string()]
        ));
    }

    #[test]
    fn cors_filter_builds_for_wildcard_and_explicit_origins() {
        let _ = build_cors(&["*".to_string()]);
        let _ = build_cors(&["https://example.com".to_string()]);
    }

    #[test]
    fn ready_response_requires_storage_up_and_not_draining() {
        let (status, body) = readiness_response(true, false);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.status, "ok");
        assert_eq!(body.storage, "up");

        let (status, body) = readiness_response(false, false);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.status, "unhealthy");
        assert_eq!(body.storage, "down");

        let (status, body) = readiness_response(true, true);
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.status, "draining");
        assert_eq!(body.storage, "up");
    }

    #[test]
    fn metrics_response_uses_prometheus_content_type() {
        let response = response_with_text_body(
            StatusCode::OK,
            b"mapae_auth_init_total 0\n".to_vec(),
            PROMETHEUS_CONTENT_TYPE,
        );

        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            PROMETHEUS_CONTENT_TYPE
        );
        assert!(String::from_utf8(response.into_body())
            .unwrap()
            .contains("mapae_auth_init_total"));
    }
}
