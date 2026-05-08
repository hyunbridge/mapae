mod auth;
mod config;
mod logging;
mod storage;
mod transport;

use anyhow::Context;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::timeout;
use tracing::{error, info};

const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

fn request_shutdown(shutdown_tx: &watch::Sender<bool>) {
    let _ = shutdown_tx.send(true);
}

async fn wait_or_abort(mut task: JoinHandle<anyhow::Result<()>>) {
    if timeout(SHUTDOWN_GRACE_PERIOD, &mut task).await.is_err() {
        task.abort();
        let _ = task.await;
    }
}

async fn wait_or_abort_all(
    smtp_task: JoinHandle<anyhow::Result<()>>,
    http_task: JoinHandle<anyhow::Result<()>>,
) {
    tokio::join!(wait_or_abort(smtp_task), wait_or_abort(http_task));
}

fn task_result(
    name: &'static str,
    result: Result<anyhow::Result<()>, JoinError>,
) -> anyhow::Result<()> {
    match result {
        Ok(Ok(())) => {
            info!("{} server stopped", name);
            Ok(())
        }
        Ok(Err(err)) => {
            error!("{} server error: {}", name, err);
            Err(err).with_context(|| format!("{name} server stopped"))
        }
        Err(err) => Err(err).with_context(|| format!("{name} task failed")),
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

    let smtp_config = settings.clone();
    let http_config = settings.clone();
    let smtp_auth = auth_service.clone();
    let http_auth = auth_service.clone();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut smtp_task = tokio::spawn(transport::smtp::run(
        smtp_config,
        smtp_auth,
        shutdown_rx.clone(),
    ));
    let mut http_task = tokio::spawn(transport::http::run(http_config, http_auth, shutdown_rx));

    let result = tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down...");
            request_shutdown(&shutdown_tx);
            wait_or_abort_all(smtp_task, http_task).await;
            Ok(())
        }
        result = &mut smtp_task => {
            let result = task_result("SMTP", result);
            request_shutdown(&shutdown_tx);
            wait_or_abort(http_task).await;
            result
        },
        result = &mut http_task => {
            let result = task_result("HTTP", result);
            request_shutdown(&shutdown_tx);
            wait_or_abort(smtp_task).await;
            result
        },
    };

    result?;
    Ok(())
}
