pub mod http;
pub mod parser;
pub mod smtp;

/// 허용하는 최대 SMTP DATA payload 크기.
pub const DATA_SIZE_LIMIT_BYTES: usize = 128 * 1024;
