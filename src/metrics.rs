use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

pub static METRICS: Metrics = Metrics::new();

pub struct Metrics {
    auth_init_total: AtomicU64,
    auth_check_total: AtomicU64,
    auth_check_signed_total: AtomicU64,
    smtp_sessions_total: AtomicU64,
    spf_pass_total: AtomicU64,
    spf_fail_total: AtomicU64,
    spf_tempfail_total: AtomicU64,
    nonce_consumed_total: AtomicU64,
    nonce_not_found_total: AtomicU64,
    redis_errors_total: AtomicU64,
    http_connection_limit_rejections_total: AtomicU64,
    smtp_connection_limit_rejections_total: AtomicU64,
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            auth_init_total: AtomicU64::new(0),
            auth_check_total: AtomicU64::new(0),
            auth_check_signed_total: AtomicU64::new(0),
            smtp_sessions_total: AtomicU64::new(0),
            spf_pass_total: AtomicU64::new(0),
            spf_fail_total: AtomicU64::new(0),
            spf_tempfail_total: AtomicU64::new(0),
            nonce_consumed_total: AtomicU64::new(0),
            nonce_not_found_total: AtomicU64::new(0),
            redis_errors_total: AtomicU64::new(0),
            http_connection_limit_rejections_total: AtomicU64::new(0),
            smtp_connection_limit_rejections_total: AtomicU64::new(0),
        }
    }

    pub fn inc_auth_init(&self) {
        self.auth_init_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_check(&self) {
        self.auth_check_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_check_signed(&self) {
        self.auth_check_signed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_smtp_session(&self) {
        self.smtp_sessions_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_spf_pass(&self) {
        self.spf_pass_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_spf_fail(&self) {
        self.spf_fail_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_spf_tempfail(&self) {
        self.spf_tempfail_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nonce_consumed(&self) {
        self.nonce_consumed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_nonce_not_found(&self) {
        self.nonce_not_found_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_redis_error(&self) {
        self.redis_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_http_connection_limit_rejection(&self) {
        self.http_connection_limit_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_smtp_connection_limit_rejection(&self) {
        self.smtp_connection_limit_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        self.write_counter(&mut out, "mapae_auth_init_total", &self.auth_init_total);
        self.write_counter(&mut out, "mapae_auth_check_total", &self.auth_check_total);
        self.write_counter(
            &mut out,
            "mapae_auth_check_signed_total",
            &self.auth_check_signed_total,
        );
        self.write_counter(
            &mut out,
            "mapae_smtp_sessions_total",
            &self.smtp_sessions_total,
        );
        self.write_counter(&mut out, "mapae_spf_pass_total", &self.spf_pass_total);
        self.write_counter(&mut out, "mapae_spf_fail_total", &self.spf_fail_total);
        self.write_counter(
            &mut out,
            "mapae_spf_tempfail_total",
            &self.spf_tempfail_total,
        );
        self.write_counter(
            &mut out,
            "mapae_nonce_consumed_total",
            &self.nonce_consumed_total,
        );
        self.write_counter(
            &mut out,
            "mapae_nonce_not_found_total",
            &self.nonce_not_found_total,
        );
        self.write_counter(
            &mut out,
            "mapae_redis_errors_total",
            &self.redis_errors_total,
        );
        self.write_counter(
            &mut out,
            "mapae_http_connection_limit_rejections_total",
            &self.http_connection_limit_rejections_total,
        );
        self.write_counter(
            &mut out,
            "mapae_smtp_connection_limit_rejections_total",
            &self.smtp_connection_limit_rejections_total,
        );
        out
    }

    fn write_counter(&self, out: &mut String, name: &str, value: &AtomicU64) {
        writeln!(out, "# TYPE {name} counter").expect("writing to String cannot fail");
        writeln!(out, "{name} {}", value.load(Ordering::Relaxed))
            .expect("writing to String cannot fail");
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;

    #[test]
    fn render_prometheus_includes_core_metrics() {
        let metrics = Metrics::new();
        metrics.inc_auth_init();
        metrics.inc_nonce_consumed();

        let body = metrics.render_prometheus();
        assert!(body.contains("# TYPE mapae_auth_init_total counter"));
        assert!(body.contains("mapae_auth_init_total 1"));
        assert!(body.contains("mapae_nonce_consumed_total 1"));
        assert!(body.contains("mapae_redis_errors_total 0"));
    }
}
