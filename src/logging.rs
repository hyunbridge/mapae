use tracing::Level;
use tracing_subscriber::EnvFilter;

pub fn init(debug: bool) {
    let level = if debug { Level::DEBUG } else { Level::INFO };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level.to_string()));

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(filter)
        .init();
}
