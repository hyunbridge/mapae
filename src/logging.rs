use tracing_subscriber::filter::LevelFilter;

pub fn init(debug: bool) {
    let default_level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let level = std::env::var("RUST_LOG")
        .ok()
        .and_then(|value| parse_log_level(&value))
        .unwrap_or(default_level);

    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(level)
        .init();
}

fn parse_log_level(value: &str) -> Option<LevelFilter> {
    let directive = value.split(',').next()?.trim().to_ascii_lowercase();
    match directive.as_str() {
        "trace" => Some(LevelFilter::TRACE),
        "debug" => Some(LevelFilter::DEBUG),
        "info" => Some(LevelFilter::INFO),
        "warn" | "warning" => Some(LevelFilter::WARN),
        "error" => Some(LevelFilter::ERROR),
        "off" => Some(LevelFilter::OFF),
        _ => None,
    }
}
