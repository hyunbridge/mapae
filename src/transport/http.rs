use anyhow::Context;
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
use crate::config::Settings;

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    storage: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    detail: String,
}

const HTTP_READ_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(15);
const HTTP_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const ERROR_INTERNAL_SERVER: &str = "Internal server error";
const ERROR_INVALID_AUTH_ID: &str = "Invalid auth_id";

/// 프론트엔드 및 백엔드 클라이언트가 접근하는 HTTP API 데몬을 실행합니다.
///
/// 인증 세션 생성, 상태 폴링 검사(`/auth/check`), 보안 토큰 발급,
/// 그리고 JWKS 엔드포인트를 `warp` 웹 프레임워크를 기반으로 제공합니다.
pub async fn run(
    config: Arc<Settings>,
    auth_service: Arc<Service>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let auth = auth_service.clone();
    let cors_origins: Vec<String> = config.cors_allow_origins.clone();

    let cors = {
        let builder = warp::cors()
            .allow_methods(vec!["GET", "POST", "OPTIONS"])
            .allow_headers(vec!["*"]);

        if cors_origins.iter().any(|origin| origin == "*") {
            builder.allow_any_origin().build()
        } else {
            builder
                .allow_origins(cors_origins.iter().map(|origin| origin.as_str()))
                .build()
        }
    };

    let health = warp::path("health")
        .and(warp::path::end())
        .and(warp::get())
        .and(with_auth(auth.clone()))
        .and_then(health_handler);

    let auth_init = warp::path("auth")
        .and(warp::path("init"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_auth(auth.clone()))
        .and_then(auth_init_handler);

    let auth_check = warp::path("auth")
        .and(warp::path("check"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(warp::get())
        .and(with_auth(auth.clone()))
        .and_then(auth_check_handler);

    let auth_check_signed = warp::path("auth")
        .and(warp::path("check-signed"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(warp::get())
        .and(with_auth(auth.clone()))
        .and_then(auth_check_signed_handler);

    let jwks = warp::path(".well-known")
        .and(warp::path("jwks.json"))
        .and(warp::path::end())
        .and(warp::get())
        .and(with_auth(auth.clone()))
        .and_then(jwks_handler);

    let routes = health
        .or(auth_init)
        .or(auth_check)
        .or(auth_check_signed)
        .or(jwks)
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
                    let service = warp::service(routes);
                    let service = hyper_util::service::TowerToHyperService::new(service);

                    let mut builder = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    );
                    builder
                        .http1()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .header_read_timeout(Some(HTTP_READ_HEADER_TIMEOUT))
                        .keep_alive(true);

                    if let Err(err) = builder.serve_connection_with_upgrades(io, service).await {
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
    if let Err(err) = stream
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        )
        .await
    {
        warn!("HTTP reject write failed: {}", err);
    }
    if let Err(err) = stream.shutdown().await {
        warn!("HTTP reject shutdown failed: {}", err);
    }
}

fn with_auth(
    auth: Arc<Service>,
) -> impl Filter<Extract = (Arc<Service>,), Error = Infallible> + Clone {
    warp::any().map(move || auth.clone())
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

async fn auth_init_handler(auth: Arc<Service>) -> Result<impl Reply, Infallible> {
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
    let mut response = warp::http::Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn error_response(detail: &str) -> ErrorResponse {
    ErrorResponse {
        detail: detail.to_string(),
    }
}
