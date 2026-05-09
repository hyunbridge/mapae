use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::{io, io::ErrorKind};

use anyhow::Context;
use mail_auth::{spf::verify::SpfParameters, MessageAuthenticator, SpfResult};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::io::SyncIoBridge;
use tracing::{error, info, warn};

use super::{parser, DATA_SIZE_LIMIT_BYTES};
use crate::auth::Service;
use crate::config::Settings;
use crate::metrics::METRICS;

const APP_NAME: &str = "MAPAE";
const SMTP_COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const SMTP_DATA_TIMEOUT: Duration = Duration::from_secs(300);
const SMTP_SESSION_TIMEOUT: Duration = Duration::from_secs(900);
const SMTP_MAX_LINE_BYTES: usize = 8192;

/// 통신사로부터 발송되는 MMS 이메일을 수신하는 비동기 SMTP 데몬을 실행합니다.
///
/// 연결 제한(Connection Limit) 및 타임아웃을 적용하여 DoS 공격을 방어하며,
/// 수신된 이메일은 SPF(Sender Policy Framework) 검증을 거쳐 인증에 활용됩니다.
pub async fn run(
    config: Arc<Settings>,
    auth_service: Arc<Service>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let bind_addr = format!("{}:{}", config.smtp_host, config.smtp_port);
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("SMTP bind error: {bind_addr}"))?;

    let authenticator =
        MessageAuthenticator::new_system_conf().context("SPF resolver init error")?;

    info!("SMTP server listening on {}", bind_addr);

    let connection_limit = Arc::new(Semaphore::new(config.smtp_max_connections));
    let mut sessions = JoinSet::new();

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("SMTP shutdown requested");
                    break;
                }
            }
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(err)) = result {
                    warn!("SMTP session task failed: {}", err);
                }
            }
            accept = listener.accept() => {
                let (stream, peer_addr) = match accept {
                    Ok(conn) => conn,
                    Err(err) => {
                        warn!("SMTP accept error: {}", err);
                        continue;
                    }
                };
                info!("New SMTP session from {}", peer_addr);
                METRICS.inc_smtp_session();

                let Ok(permit) = connection_limit.clone().try_acquire_owned() else {
                    METRICS.inc_smtp_connection_limit_rejection();
                    warn!(
                        "Rejected SMTP session from {}: connection limit reached",
                        peer_addr
                    );
                    sessions.spawn(reject_smtp_session(stream));
                    continue;
                };

                if let Err(err) = stream.set_nodelay(true) {
                    warn!("SMTP set_nodelay failed for {}: {}", peer_addr, err);
                }

                let config = config.clone();
                let auth_service = auth_service.clone();
                let authenticator = authenticator.clone();
                sessions.spawn(async move {
                    let _permit = permit;
                    match timeout(
                        SMTP_SESSION_TIMEOUT,
                        handle_session(stream, peer_addr, config, auth_service, authenticator),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => warn!("SMTP session error from {}: {}", peer_addr, err),
                        Err(_) => warn!("SMTP session timed out from {}", peer_addr),
                    }
                });
            }
        }
    }

    while let Some(result) = sessions.join_next().await {
        if let Err(err) = result {
            warn!("SMTP session task failed: {}", err);
        }
    }

    Ok(())
}

async fn reject_smtp_session(mut stream: TcpStream) {
    if let Err(err) = stream
        .write_all(b"421 4.3.2 Too many connections\r\n")
        .await
    {
        warn!("SMTP reject write failed: {}", err);
    }
    if let Err(err) = stream.shutdown().await {
        warn!("SMTP reject shutdown failed: {}", err);
    }
}

struct SmtpSession {
    peer_addr: SocketAddr,
    mail_from: String,
    helo_domain: String,
    mail_seen: bool,
    rcpt_count: usize,
}

impl SmtpSession {
    fn new(peer_addr: SocketAddr) -> Self {
        Self {
            peer_addr,
            mail_from: String::new(),
            helo_domain: String::new(),
            mail_seen: false,
            rcpt_count: 0,
        }
    }

    fn reset_transaction(&mut self) {
        self.mail_from.clear();
        self.mail_seen = false;
        self.rcpt_count = 0;
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SmtpReply {
    status: u16,
    message: &'static str,
    enhanced: Option<&'static str>,
}

impl SmtpReply {
    const fn new(status: u16, message: &'static str, enhanced: Option<&'static str>) -> Self {
        Self {
            status,
            message,
            enhanced,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SessionAction {
    Continue,
    Close,
}

async fn handle_session(
    stream: TcpStream,
    peer_addr: SocketAddr,
    config: Arc<Settings>,
    auth_service: Arc<Service>,
    authenticator: MessageAuthenticator,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut session = SmtpSession::new(peer_addr);

    write_line(&mut reader, &format!("220 {APP_NAME} ESMTP ready\r\n")).await?;

    loop {
        let line =
            match read_line_limited(&mut reader, SMTP_MAX_LINE_BYTES, SMTP_COMMAND_TIMEOUT).await {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(()),
                Err(err) if err.kind() == ErrorKind::InvalidData => {
                    write_reply(
                        &mut reader,
                        SmtpReply::new(500, "Line too long", Some("5.5.2")),
                    )
                    .await?;
                    return Ok(());
                }
                Err(err) if err.kind() == ErrorKind::TimedOut => return Ok(()),
                Err(err) => return Err(err),
            };

        let command = String::from_utf8_lossy(parser::trim_crlf(&line));
        let action = handle_smtp_command(
            &mut reader,
            &command,
            &mut session,
            &config,
            &auth_service,
            &authenticator,
        )
        .await?;
        if action == SessionAction::Close {
            return Ok(());
        }
    }
}

async fn handle_smtp_command(
    reader: &mut BufReader<TcpStream>,
    command: &str,
    session: &mut SmtpSession,
    config: &Settings,
    auth_service: &Service,
    authenticator: &MessageAuthenticator,
) -> io::Result<SessionAction> {
    let upper = command.to_ascii_uppercase();
    if upper.starts_with("EHLO ") || upper == "EHLO" {
        handle_helo_command(reader, session, command, true).await?;
    } else if upper.starts_with("HELO ") || upper == "HELO" {
        handle_helo_command(reader, session, command, false).await?;
    } else if upper.starts_with("MAIL FROM:") {
        handle_mail_command(reader, session, command).await?;
    } else if upper.starts_with("RCPT TO:") {
        handle_rcpt_command(reader, config, session, command).await?;
    } else if upper == "DATA" {
        return handle_data_command(reader, config, auth_service, authenticator, session).await;
    } else if upper == "RSET" {
        session.reset_transaction();
        write_reply(reader, SmtpReply::new(250, "OK", None)).await?;
    } else if upper == "NOOP" {
        write_reply(reader, SmtpReply::new(250, "OK", None)).await?;
    } else if upper == "QUIT" {
        write_reply(reader, SmtpReply::new(221, "Bye", None)).await?;
        return Ok(SessionAction::Close);
    } else {
        write_reply(
            reader,
            SmtpReply::new(502, "Command not implemented", Some("5.5.1")),
        )
        .await?;
    }

    Ok(SessionAction::Continue)
}

async fn handle_helo_command(
    reader: &mut BufReader<TcpStream>,
    session: &mut SmtpSession,
    command: &str,
    extended: bool,
) -> io::Result<()> {
    let Some(domain) = parse_helo_domain(command) else {
        write_reply(reader, SmtpReply::new(501, "Missing domain", Some("5.5.2"))).await?;
        return Ok(());
    };

    session.helo_domain = domain.to_string();
    if extended {
        write_line(
            reader,
            &format!("250-{APP_NAME}\r\n250 SIZE {DATA_SIZE_LIMIT_BYTES}\r\n"),
        )
        .await
    } else {
        write_line(reader, &format!("250 {APP_NAME}\r\n")).await
    }
}

async fn handle_mail_command(
    reader: &mut BufReader<TcpStream>,
    session: &mut SmtpSession,
    command: &str,
) -> io::Result<()> {
    let Some(from) = parse_smtp_path(&command[10..]) else {
        write_reply(reader, SmtpReply::new(501, "Invalid sender", Some("5.1.7"))).await?;
        return Ok(());
    };

    session.mail_from = from;
    session.mail_seen = true;
    session.rcpt_count = 0;
    write_reply(reader, SmtpReply::new(250, "OK", None)).await
}

async fn handle_rcpt_command(
    reader: &mut BufReader<TcpStream>,
    config: &Settings,
    session: &mut SmtpSession,
    command: &str,
) -> io::Result<()> {
    if !session.mail_seen {
        write_reply(
            reader,
            SmtpReply::new(503, "Need MAIL FROM first", Some("5.5.1")),
        )
        .await?;
        return Ok(());
    }

    let Some(to) = parse_smtp_path(&command[8..]) else {
        write_reply(
            reader,
            SmtpReply::new(501, "Invalid recipient", Some("5.1.3")),
        )
        .await?;
        return Ok(());
    };

    match handle_rcpt(config, session, &to) {
        Ok(()) => {
            session.rcpt_count += 1;
            write_reply(reader, SmtpReply::new(250, "OK", None)).await
        }
        Err(reply) => write_reply(reader, reply).await,
    }
}

async fn handle_data_command(
    reader: &mut BufReader<TcpStream>,
    config: &Settings,
    auth_service: &Service,
    authenticator: &MessageAuthenticator,
    session: &mut SmtpSession,
) -> io::Result<SessionAction> {
    if !session.mail_seen || session.rcpt_count == 0 {
        write_reply(
            reader,
            SmtpReply::new(503, "Need MAIL FROM and RCPT TO first", Some("5.5.1")),
        )
        .await?;
        return Ok(SessionAction::Continue);
    }

    write_reply(
        reader,
        SmtpReply::new(354, "End data with <CR><LF>.<CR><LF>", None),
    )
    .await?;

    match receive_and_process_data(reader, config, auth_service, authenticator, session).await {
        Ok(()) => write_reply(reader, SmtpReply::new(250, "OK", None)).await?,
        Err(reply) => {
            let close_after_reply = reply.status == 552;
            write_reply(reader, reply).await?;
            if close_after_reply {
                return Ok(SessionAction::Close);
            }
        }
    }

    session.reset_transaction();
    Ok(SessionAction::Continue)
}

async fn receive_and_process_data(
    reader: &mut BufReader<TcpStream>,
    config: &Settings,
    auth_service: &Service,
    authenticator: &MessageAuthenticator,
    session: &SmtpSession,
) -> Result<(), SmtpReply> {
    if config.dump_inbound {
        match read_data(reader).await {
            Ok(data) => {
                process_email_data(config, auth_service, authenticator, session, data).await
            }
            Err(reply) => Err(reply),
        }
    } else {
        match stream_extract_data(reader).await {
            Ok(extract_result) => {
                process_extracted_email(
                    config,
                    auth_service,
                    authenticator,
                    session,
                    extract_result,
                    None,
                )
                .await
            }
            Err(reply) => Err(reply),
        }
    }
}

async fn write_reply(reader: &mut BufReader<TcpStream>, reply: SmtpReply) -> io::Result<()> {
    let stream = reader.get_mut();
    let status = smtp_status_bytes(reply.status);
    stream.write_all(&status).await?;
    stream.write_all(b" ").await?;
    if let Some(enhanced) = reply.enhanced {
        stream.write_all(enhanced.as_bytes()).await?;
        stream.write_all(b" ").await?;
    }
    stream.write_all(reply.message.as_bytes()).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await
}

fn smtp_status_bytes(status: u16) -> [u8; 3] {
    debug_assert!((100..=999).contains(&status));
    [
        b'0' + ((status / 100) % 10) as u8,
        b'0' + ((status / 10) % 10) as u8,
        b'0' + (status % 10) as u8,
    ]
}

async fn write_line(reader: &mut BufReader<TcpStream>, line: &str) -> io::Result<()> {
    let stream = reader.get_mut();
    stream.write_all(line.as_bytes()).await?;
    stream.flush().await
}

async fn read_data(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, SmtpReply> {
    let mut data = Vec::new();
    let mut too_large = false;

    loop {
        let line = read_line_limited(reader, DATA_SIZE_LIMIT_BYTES + 3, SMTP_DATA_TIMEOUT)
            .await
            .map_err(|err| {
                if err.kind() == ErrorKind::InvalidData {
                    SmtpReply::new(552, "Message size exceeds limit", Some("5.3.4"))
                } else {
                    SmtpReply::new(451, "Temporary server error", Some("4.3.0"))
                }
            })?;
        let Some(line) = line else {
            return Err(SmtpReply::new(550, "Invalid message", Some("5.6.0")));
        };

        let trimmed = parser::trim_crlf(&line);
        if trimmed == b"." {
            break;
        }

        let body_line = if line.starts_with(b"..") {
            &line[1..]
        } else {
            line.as_slice()
        };
        if data.len().saturating_add(body_line.len()) > DATA_SIZE_LIMIT_BYTES {
            too_large = true;
        } else if !too_large {
            data.extend_from_slice(body_line);
        }
    }

    if too_large {
        Err(SmtpReply::new(
            552,
            "Message size exceeds limit",
            Some("5.3.4"),
        ))
    } else {
        Ok(data)
    }
}

async fn stream_extract_data(
    reader: &mut BufReader<TcpStream>,
) -> Result<parser::ExtractResult, SmtpReply> {
    let (mut body_writer, body_reader) = tokio::io::duplex(64 * 1024);
    let runtime = tokio::runtime::Handle::current();
    let parser_task = tokio::task::spawn_blocking(move || {
        parser::extract_header_from_and_nonce_stream(
            SyncIoBridge::new_with_handle(body_reader, runtime),
            DATA_SIZE_LIMIT_BYTES,
        )
    });

    let mut read_error = None;
    let mut parser_finished_before_terminator = false;

    loop {
        if parser_task.is_finished() {
            parser_finished_before_terminator = true;
            break;
        }

        let line =
            match read_line_limited(reader, DATA_SIZE_LIMIT_BYTES + 3, SMTP_DATA_TIMEOUT).await {
                Ok(Some(line)) => line,
                Ok(None) => {
                    read_error = Some(SmtpReply::new(550, "Invalid message", Some("5.6.0")));
                    break;
                }
                Err(err) => {
                    read_error = Some(if err.kind() == ErrorKind::InvalidData {
                        SmtpReply::new(552, "Message size exceeds limit", Some("5.3.4"))
                    } else {
                        SmtpReply::new(451, "Temporary server error", Some("4.3.0"))
                    });
                    break;
                }
            };

        let trimmed = parser::trim_crlf(&line);
        if trimmed == b"." {
            break;
        }

        let body_line = if line.starts_with(b"..") {
            &line[1..]
        } else {
            line.as_slice()
        };

        if body_writer.write_all(body_line).await.is_err() {
            parser_finished_before_terminator = true;
            break;
        }
    }

    drop(body_writer);

    if let Some(reply) = read_error {
        let _ = parser_task.await;
        return Err(reply);
    }

    if parser_finished_before_terminator {
        if let Err(reply) = drain_data_to_terminator(reader).await {
            let _ = parser_task.await;
            return Err(reply);
        }
    }

    parser_task
        .await
        .map_err(|err| {
            error!("MIME parser task failed: {}", err);
            SmtpReply::new(451, "Temporary server error", Some("4.3.0"))
        })?
        .map_err(|err| {
            error!("MIME parse error: {}", err);
            map_stream_parse_error(&err)
        })
}

async fn drain_data_to_terminator(reader: &mut BufReader<TcpStream>) -> Result<(), SmtpReply> {
    let mut bytes_read = 0usize;

    loop {
        let line = read_line_limited(reader, DATA_SIZE_LIMIT_BYTES + 3, SMTP_DATA_TIMEOUT)
            .await
            .map_err(|err| {
                if err.kind() == ErrorKind::InvalidData {
                    SmtpReply::new(552, "Message size exceeds limit", Some("5.3.4"))
                } else {
                    SmtpReply::new(451, "Temporary server error", Some("4.3.0"))
                }
            })?;
        let Some(line) = line else {
            return Err(SmtpReply::new(550, "Invalid message", Some("5.6.0")));
        };

        if parser::trim_crlf(&line) == b"." {
            return Ok(());
        }

        bytes_read = bytes_read.saturating_add(line.len());
        if bytes_read > DATA_SIZE_LIMIT_BYTES {
            return Err(SmtpReply::new(
                552,
                "Message size exceeds limit",
                Some("5.3.4"),
            ));
        }
    }
}

async fn read_line_limited(
    reader: &mut BufReader<TcpStream>,
    limit: usize,
    read_timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    let fut = async {
        let mut taker = reader.take(limit.saturating_add(1) as u64);
        taker.read_until(b'\n', &mut line).await
    };

    match timeout(read_timeout, fut).await {
        Ok(Ok(0)) => {
            if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            }
        }
        Ok(Ok(_)) => {
            if line.len() > limit {
                Err(io::Error::new(ErrorKind::InvalidData, "SMTP line too long"))
            } else {
                Ok(Some(line))
            }
        }
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(ErrorKind::TimedOut, "SMTP read timeout")),
    }
}

fn parse_smtp_path(value: &str) -> Option<String> {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('<') {
        let end = rest.find('>')?;
        return Some(rest[..end].trim().to_string());
    }

    value
        .split_whitespace()
        .next()
        .map(|addr| addr.trim().to_string())
        .filter(|addr| !addr.is_empty())
}

fn parse_helo_domain(command: &str) -> Option<&str> {
    let domain = command.get(4..)?.trim();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn handle_rcpt(config: &Settings, session: &SmtpSession, to: &str) -> Result<(), SmtpReply> {
    let inbound = config.sms_inbound_address.trim();
    // 빈 inbound 주소는 기존 Go 구현 및 개발 환경과의 호환을 위해 모든 RCPT를 허용한다.
    // 운영 기본값은 verify@example.com 같은 명시적 수신 주소를 두고 이 경로를 타지 않게 한다.
    if !is_rcpt_allowed(inbound, to.trim()) {
        warn!("Rejected RCPT TO for {} from {}", to, session.peer_addr);
        return Err(SmtpReply::new(
            550,
            "Not relaying to that address",
            Some("5.7.1"),
        ));
    }

    if session.rcpt_count >= 1 {
        return Err(SmtpReply::new(452, "Too many recipients", Some("4.5.3")));
    }

    Ok(())
}

async fn process_email_data(
    config: &Settings,
    auth_service: &Service,
    authenticator: &MessageAuthenticator,
    session: &SmtpSession,
    data: Vec<u8>,
) -> Result<(), SmtpReply> {
    let (data, extract_result) = extract_email_data(data).await?;

    process_extracted_email(
        config,
        auth_service,
        authenticator,
        session,
        extract_result,
        Some(data.as_slice()),
    )
    .await
}

async fn extract_email_data(data: Vec<u8>) -> Result<(Vec<u8>, parser::ExtractResult), SmtpReply> {
    tokio::task::spawn_blocking(move || {
        parser::extract_header_from_and_nonce(data.as_slice(), DATA_SIZE_LIMIT_BYTES)
            .map(|extract_result| (data, extract_result))
    })
    .await
    .map_err(|err| {
        error!("MIME parser task failed: {}", err);
        SmtpReply::new(451, "Temporary server error", Some("4.3.0"))
    })?
    .map_err(|err| {
        error!("MIME parse error: {}", err);
        map_stream_parse_error(&err)
    })
}

async fn process_extracted_email(
    config: &Settings,
    auth_service: &Service,
    authenticator: &MessageAuthenticator,
    session: &SmtpSession,
    extract_result: parser::ExtractResult,
    data_preview: Option<&[u8]>,
) -> Result<(), SmtpReply> {
    let peer = session.peer_addr.to_string();
    let header_from = extract_result.header_from;
    let nonce = extract_result.nonce;
    let bytes_read = extract_result.bytes_read;

    log_inbound_email(config, session, &header_from, &peer, data_preview);

    let sender =
        select_verified_sender(config, authenticator, session, &header_from, &peer).await?;

    if !parser::is_valid_nonce(&nonce) {
        warn!("Invalid nonce format from {}", peer);
        return Err(SmtpReply::new(550, "Invalid nonce", Some("5.7.1")));
    }

    let auth_id = store_verification_by_nonce(auth_service, &nonce, &sender).await?;

    info!(
        "Stored verification for auth_id={} phone={:?} carrier={:?} bytes_read={}",
        auth_id,
        sender.phone,
        Some(sender.carrier.as_str()),
        bytes_read
    );
    Ok(())
}

fn log_inbound_email(
    config: &Settings,
    session: &SmtpSession,
    header_from: &str,
    peer: &str,
    data_preview: Option<&[u8]>,
) {
    if !config.dump_inbound {
        return;
    }

    info!(
        "MAIL FROM: {} | HEADER FROM: {} | PEER: {}",
        session.mail_from, header_from, peer
    );
    if let Some(data) = data_preview {
        info!(
            "BODY: {}",
            String::from_utf8_lossy(data)
                .chars()
                .take(500)
                .collect::<String>()
        );
    }
}

struct VerifiedSender {
    phone: Option<String>,
    carrier: String,
}

struct SenderCandidate {
    phone: Option<String>,
    carrier: Option<String>,
    sender: Option<String>,
}

impl SenderCandidate {
    fn from_address(value: &str) -> Self {
        let (phone, carrier) = parser::extract_phone_and_carrier(value);
        Self {
            phone,
            carrier,
            sender: normalize_email_address(value),
        }
    }

    fn has_carrier(&self) -> bool {
        self.carrier.is_some()
    }

    fn into_verified_sender(self) -> Option<VerifiedSender> {
        Some(VerifiedSender {
            phone: self.phone,
            carrier: self.carrier?,
        })
    }
}

struct SenderSpfChecks {
    envelope: SpfCheck,
    header: Option<SpfCheck>,
}

impl SenderSpfChecks {
    fn header_pass(&self) -> bool {
        self.header.as_ref().is_some_and(|check| check.pass)
    }

    fn any_pass(&self) -> bool {
        self.envelope.pass || self.header_pass()
    }

    fn has_temp_error(&self) -> bool {
        self.envelope.temp_error || self.header.as_ref().is_some_and(|check| check.temp_error)
    }
}

async fn select_verified_sender(
    config: &Settings,
    authenticator: &MessageAuthenticator,
    session: &SmtpSession,
    header_from: &str,
    peer: &str,
) -> Result<VerifiedSender, SmtpReply> {
    let envelope = SenderCandidate::from_address(&session.mail_from);
    let header = SenderCandidate::from_address(header_from);
    let peer_ip = session.peer_addr.ip();
    let host_domain = smtp_host_domain(config);
    let checks = check_sender_spf(
        authenticator,
        peer_ip,
        session.helo_domain.as_str(),
        host_domain.as_str(),
        &envelope,
        &header,
    )
    .await;

    ensure_spf_accepted(&checks, peer, &session.mail_from, header_from)?;

    let Some(sender) = choose_verified_sender(envelope, header, &checks) else {
        warn!("Carrier domain not recognized from {}", peer);
        return Err(SmtpReply::new(550, "Invalid carrier domain", Some("5.7.1")));
    };

    Ok(sender)
}

async fn check_sender_spf(
    authenticator: &MessageAuthenticator,
    peer_ip: IpAddr,
    helo_domain: &str,
    host_domain: &str,
    envelope: &SenderCandidate,
    header: &SenderCandidate,
) -> SenderSpfChecks {
    let envelope_check = check_spf(
        authenticator,
        peer_ip,
        envelope.sender.as_deref(),
        helo_domain,
        host_domain,
    )
    .await;

    let envelope_usable = envelope_check.pass && envelope.has_carrier();
    let header_check = if envelope_usable {
        None
    } else {
        Some(
            check_spf(
                authenticator,
                peer_ip,
                header.sender.as_deref(),
                helo_domain,
                host_domain,
            )
            .await,
        )
    };

    SenderSpfChecks {
        envelope: envelope_check,
        header: header_check,
    }
}

fn ensure_spf_accepted(
    checks: &SenderSpfChecks,
    peer: &str,
    mail_from: &str,
    header_from: &str,
) -> Result<(), SmtpReply> {
    if checks.any_pass() {
        METRICS.inc_spf_pass();
        return Ok(());
    }

    if checks.has_temp_error() {
        METRICS.inc_spf_tempfail();
        warn!(
            "SPF temperror: ip={} mail_from={} header_from={}",
            peer, mail_from, header_from
        );
        return Err(SmtpReply::new(451, "SPF temperror", Some("4.7.0")));
    }

    METRICS.inc_spf_fail();
    warn!(
        "SPF fail: ip={} mail_from={} header_from={}",
        peer, mail_from, header_from
    );
    Err(SmtpReply::new(550, "SPF fail", Some("5.7.1")))
}

fn choose_verified_sender(
    envelope: SenderCandidate,
    header: SenderCandidate,
    checks: &SenderSpfChecks,
) -> Option<VerifiedSender> {
    if checks.envelope.pass && envelope.has_carrier() {
        return envelope.into_verified_sender();
    }

    if checks.header_pass() && header.has_carrier() {
        return header.into_verified_sender();
    }

    None
}

async fn store_verification_by_nonce(
    auth_service: &Service,
    nonce: &str,
    sender: &VerifiedSender,
) -> Result<String, SmtpReply> {
    let Some(auth_id) = auth_service
        .consume_nonce_and_store_verified(
            nonce,
            sender.phone.as_deref(),
            Some(sender.carrier.as_str()),
        )
        .await
        .map_err(|e| {
            error!("Failed to consume nonce and store verification: {}", e);
            SmtpReply::new(451, "Temporary server error", Some("4.3.0"))
        })?
    else {
        METRICS.inc_nonce_not_found();
        warn!("Nonce not found or expired: {}", nonce);
        return Err(SmtpReply::new(550, "Invalid nonce", Some("5.7.1")));
    };

    METRICS.inc_nonce_consumed();
    Ok(auth_id)
}

fn normalize_email_address(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "<>" {
        return None;
    }

    if let Ok(addrs) = mailparse::addrparse(trimmed) {
        if !addrs.is_empty() {
            match &addrs[0] {
                mailparse::MailAddr::Single(s) if !s.addr.is_empty() => {
                    return Some(s.addr.clone());
                }
                mailparse::MailAddr::Group(g) => {
                    if let Some(first) = g.addrs.first() {
                        if !first.addr.is_empty() {
                            return Some(first.addr.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    None
}

fn map_stream_parse_error(err: &parser::ParseError) -> SmtpReply {
    if err.is_message_too_large() {
        return SmtpReply::new(552, "Message size exceeds limit", Some("5.3.4"));
    }

    SmtpReply::new(550, "Invalid message", Some("5.6.0"))
}

fn is_rcpt_allowed(inbound: &str, to: &str) -> bool {
    inbound.trim().is_empty() || to.trim().eq_ignore_ascii_case(inbound.trim())
}

#[derive(Default)]
struct SpfCheck {
    pass: bool,
    temp_error: bool,
}

async fn check_spf(
    authenticator: &MessageAuthenticator,
    peer_ip: IpAddr,
    sender: Option<&str>,
    helo_domain: &str,
    host_domain: &str,
) -> SpfCheck {
    let Some(sender) = sender.filter(|sender| !sender.is_empty()) else {
        return SpfCheck {
            pass: false,
            temp_error: false,
        };
    };

    let result = authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            peer_ip,
            helo_domain,
            host_domain,
            sender,
        ))
        .await
        .result();

    SpfCheck {
        pass: result == SpfResult::Pass,
        temp_error: result == SpfResult::TempError,
    }
}

fn smtp_host_domain(config: &Settings) -> String {
    normalize_email_address(&config.sms_inbound_address)
        .and_then(|address| {
            address
                .rsplit_once('@')
                .map(|(_, domain)| domain.trim().to_string())
        })
        .filter(|domain| !domain.is_empty())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        choose_verified_sender, ensure_spf_accepted, is_rcpt_allowed, map_stream_parse_error,
        normalize_email_address, parse_helo_domain, parse_smtp_path, parser, read_data,
        read_line_limited, smtp_host_domain, smtp_status_bytes, stream_extract_data,
        SenderCandidate, SenderSpfChecks, SmtpReply, SpfCheck, APP_NAME, DATA_SIZE_LIMIT_BYTES,
        SMTP_COMMAND_TIMEOUT, SMTP_MAX_LINE_BYTES,
    };
    use crate::config::Settings;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[test]
    fn normalize_email_address_accepts_common_smtp_paths() {
        assert_eq!(
            normalize_email_address("<verify@example.com>").as_deref(),
            Some("verify@example.com")
        );
        assert_eq!(
            normalize_email_address("verify@example.com").as_deref(),
            Some("verify@example.com")
        );
        assert_eq!(
            normalize_email_address("Display <verify@example.com>").as_deref(),
            Some("verify@example.com")
        );
    }

    #[test]
    fn normalize_email_address_rejects_empty_sender() {
        assert_eq!(normalize_email_address("<>"), None);
        assert_eq!(normalize_email_address("  "), None);
    }

    #[test]
    fn normalize_email_address_rejects_malformed_sender() {
        assert_eq!(normalize_email_address("not-an-rfc5322 address"), None);
    }

    #[test]
    fn smtp_host_domain_uses_inbound_domain() {
        let settings = Settings {
            sms_inbound_address: "verify@example.com".to_string(),
            ..Settings::default()
        };

        assert_eq!(smtp_host_domain(&settings), "example.com");
    }

    #[test]
    fn parse_smtp_path_handles_params_and_brackets() {
        assert_eq!(
            parse_smtp_path("<verify@example.com> SIZE=123").as_deref(),
            Some("verify@example.com")
        );
        assert_eq!(parse_smtp_path("<>").as_deref(), Some(""));
        assert_eq!(
            parse_smtp_path("verify@example.com SIZE=123").as_deref(),
            Some("verify@example.com")
        );
        assert_eq!(parse_smtp_path("<missing-end"), None);
        assert_eq!(parse_smtp_path("   "), None);
    }

    #[test]
    fn parse_helo_domain_rejects_empty_domain() {
        assert_eq!(parse_helo_domain("EHLO"), None);
        assert_eq!(parse_helo_domain("EHLO   "), None);
        assert_eq!(parse_helo_domain("HELO example.com"), Some("example.com"));
    }

    #[test]
    fn map_stream_parse_error_uses_smtp_parity_status_codes() {
        let too_large =
            parser::extract_header_from_and_nonce(b"From: a@example.com\r\n\r\nx", 1).unwrap_err();
        let generic = parser::ParseError::InvalidMessage("bad mime".to_string());

        assert_eq!(
            map_stream_parse_error(&too_large),
            SmtpReply::new(552, "Message size exceeds limit", Some("5.3.4"))
        );
        assert_eq!(
            map_stream_parse_error(&generic),
            SmtpReply::new(550, "Invalid message", Some("5.6.0"))
        );
    }

    #[test]
    fn smtp_status_bytes_formats_three_digit_status() {
        assert_eq!(smtp_status_bytes(250), *b"250");
        assert_eq!(smtp_status_bytes(552), *b"552");
    }

    #[test]
    fn rcpt_policy_matches_go_behavior() {
        assert!(is_rcpt_allowed("", "verify@example.com"));
        assert!(is_rcpt_allowed("verify@example.com", "VERIFY@example.com"));
        assert!(!is_rcpt_allowed("verify@example.com", "other@example.com"));
    }

    fn sender_candidate(phone: Option<&str>, carrier: Option<&str>) -> SenderCandidate {
        SenderCandidate {
            phone: phone.map(str::to_string),
            carrier: carrier.map(str::to_string),
            sender: Some("sender@example.com".to_string()),
        }
    }

    fn spf_check(pass: bool) -> SpfCheck {
        SpfCheck {
            pass,
            ..Default::default()
        }
    }

    #[test]
    fn choose_verified_sender_prefers_valid_envelope_sender() {
        let checks = SenderSpfChecks {
            envelope: spf_check(true),
            header: Some(spf_check(true)),
        };

        let sender = choose_verified_sender(
            sender_candidate(Some("01012345678"), Some("KT")),
            sender_candidate(Some("01087654321"), Some("LGU+")),
            &checks,
        )
        .unwrap();

        assert_eq!(sender.phone.as_deref(), Some("01012345678"));
        assert_eq!(sender.carrier, "KT");
    }

    #[test]
    fn choose_verified_sender_falls_back_to_header_sender() {
        let checks = SenderSpfChecks {
            envelope: spf_check(true),
            header: Some(spf_check(true)),
        };

        let sender = choose_verified_sender(
            sender_candidate(None, None),
            sender_candidate(Some("01087654321"), Some("LGU+")),
            &checks,
        )
        .unwrap();

        assert_eq!(sender.phone.as_deref(), Some("01087654321"));
        assert_eq!(sender.carrier, "LGU+");
    }

    #[test]
    fn ensure_spf_accepted_maps_failures_to_smtp_replies() {
        let temp_error = SenderSpfChecks {
            envelope: SpfCheck {
                temp_error: true,
                ..Default::default()
            },
            header: Some(SpfCheck::default()),
        };
        assert_eq!(
            ensure_spf_accepted(
                &temp_error,
                "127.0.0.1",
                "mail@example.com",
                "hdr@example.com"
            )
            .unwrap_err(),
            SmtpReply::new(451, "SPF temperror", Some("4.7.0"))
        );

        let fail = SenderSpfChecks {
            envelope: SpfCheck::default(),
            header: Some(SpfCheck::default()),
        };
        assert_eq!(
            ensure_spf_accepted(&fail, "127.0.0.1", "mail@example.com", "hdr@example.com")
                .unwrap_err(),
            SmtpReply::new(550, "SPF fail", Some("5.7.1"))
        );
    }

    #[tokio::test]
    async fn read_data_unstuffs_and_enforces_size() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"hello\r\n..dot-stuffed\r\n.\r\n")
                .await
                .unwrap();
        });

        let (server, _) = listener.accept().await.unwrap();
        let data = read_data(&mut BufReader::new(server)).await.unwrap();
        client.await.unwrap();

        assert_eq!(
            String::from_utf8(data).unwrap(),
            "hello\r\n.dot-stuffed\r\n"
        );
        assert_eq!(APP_NAME, "MAPAE");
    }

    #[tokio::test]
    async fn read_data_reports_unexpected_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"unterminated\r\n").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let (server, _) = listener.accept().await.unwrap();
        let err = read_data(&mut BufReader::new(server)).await.unwrap_err();
        client.await.unwrap();

        assert_eq!(err, SmtpReply::new(550, "Invalid message", Some("5.6.0")));
    }

    #[tokio::test]
    async fn stream_extract_data_parses_dot_unstuffed_message() {
        let nonce = "a".repeat(64);
        let payload = format!(
            "From: user@example.com\r\nContent-Type: text/plain\r\n\r\n..leading dot\r\n[MAPAE:{nonce}]\r\n.\r\n"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(payload.as_bytes()).await.unwrap();
        });

        let (server, _) = listener.accept().await.unwrap();
        let got = stream_extract_data(&mut BufReader::new(server))
            .await
            .unwrap();
        client.await.unwrap();

        assert_eq!(got.header_from, "user@example.com");
        assert_eq!(got.nonce, nonce);
        assert!(got.bytes_read > 0);
    }

    #[tokio::test]
    async fn stream_extract_data_rejects_oversize_after_nonce() {
        let nonce = "b".repeat(64);
        let mut payload = format!("From: user@example.com\r\n\r\n[MAPAE:{nonce}]\r\n");
        for _ in 0..(DATA_SIZE_LIMIT_BYTES / 1024 + 2) {
            payload.push_str(&"x".repeat(1024));
            payload.push_str("\r\n");
        }
        payload.push_str(".\r\n");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(payload.as_bytes()).await.unwrap();
        });

        let (server, _) = listener.accept().await.unwrap();
        let err = stream_extract_data(&mut BufReader::new(server))
            .await
            .unwrap_err();
        client.await.unwrap();

        assert_eq!(
            err,
            SmtpReply::new(552, "Message size exceeds limit", Some("5.3.4"))
        );
    }

    #[tokio::test]
    async fn stream_extract_data_drains_after_parser_failure() {
        let mut payload = String::from("malformed-header\r\n");
        for _ in 0..32 {
            payload.push_str("body line after parser failure\r\n");
        }
        payload.push_str(".\r\nNOOP\r\n");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream.write_all(payload.as_bytes()).await.unwrap();
        });

        let (server, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(server);
        let err = stream_extract_data(&mut reader).await.unwrap_err();
        let next = read_line_limited(&mut reader, SMTP_MAX_LINE_BYTES, SMTP_COMMAND_TIMEOUT)
            .await
            .unwrap()
            .unwrap();
        client.await.unwrap();

        assert_eq!(err, SmtpReply::new(550, "Invalid message", Some("5.6.0")));
        assert_eq!(parser::trim_crlf(&next), b"NOOP");
    }
}
