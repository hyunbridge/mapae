mod auth;
mod config;
mod logging;
mod storage;
mod transport;

use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinSet};
use tracing::{error, info};

const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);
type ServerTaskResult = (&'static str, anyhow::Result<()>);

fn request_shutdown(shutdown_tx: &watch::Sender<bool>) {
    let _ = shutdown_tx.send(true);
}

async fn wait_or_abort_all(tasks: &mut JoinSet<ServerTaskResult>) {
    let deadline = tokio::time::sleep(SHUTDOWN_GRACE_PERIOD);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result {
                    let _ = task_result(result);
                }
            }
            _ = &mut deadline, if !tasks.is_empty() => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                break;
            }
            else => break,
        }
    }
}

fn task_result(result: Result<ServerTaskResult, JoinError>) -> anyhow::Result<()> {
    match result {
        Ok((name, Ok(()))) => {
            info!("{} server stopped", name);
            Ok(())
        }
        Ok((name, Err(err))) => {
            error!("{} server error: {}", name, err);
            Err(err).with_context(|| format!("{name} server stopped"))
        }
        Err(err) => Err(err).context("server task failed"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = Arc::new(config::Settings::load());
    logging::init(settings.debug);

    let store = if settings.use_in_memory_store {
        info!("Using in-memory store");
        storage::StoreBackend::memory(storage::memory::MemoryStore::new())
    } else {
        if settings.redis_url.trim().is_empty() {
            anyhow::bail!("REDIS_URL must be set unless USE_IN_MEMORY_STORE=true");
        }

        info!("Using Redis store");
        let store = storage::redis::RedisStore::new(
            &settings.redis_url,
            settings.redis_wait_replicas,
            settings.redis_wait_timeout_ms,
        )
        .await
        .context("Failed to initialize Redis client")?;
        storage::StoreBackend::redis(store)
    };

    let auth_service = Arc::new(
        auth::Service::new(store, &settings).context("Failed to initialize auth service")?,
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut server_tasks = JoinSet::new();

    if settings.server_mode.runs_smtp() {
        let smtp_config = settings.clone();
        let smtp_auth = auth_service.clone();
        let smtp_shutdown = shutdown_rx.clone();
        server_tasks.spawn(async move {
            (
                "SMTP",
                transport::smtp::run(smtp_config, smtp_auth, smtp_shutdown).await,
            )
        });
    }

    if settings.server_mode.runs_http() {
        let http_config = settings.clone();
        let http_auth = auth_service.clone();
        server_tasks.spawn(async move {
            (
                "HTTP",
                transport::http::run(http_config, http_auth, shutdown_rx).await,
            )
        });
    }

    let result = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
            request_shutdown(&shutdown_tx);
            wait_or_abort_all(&mut server_tasks).await;
            Ok(())
        }
        result = server_tasks.join_next() => {
            let result = result.map_or_else(
                || Ok(()),
                task_result,
            );
            request_shutdown(&shutdown_tx);
            wait_or_abort_all(&mut server_tasks).await;
            result
        },
    };

    result?;
    Ok(())
}
