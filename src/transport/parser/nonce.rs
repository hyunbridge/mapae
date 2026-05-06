use super::NONCE_HEX_LENGTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceScannerState {
    Searching,
    OpenBracket,
    M,
    Ma,
    Map,
    Mapa,
    Mapae,
    HexDigits,
}

pub(super) struct NonceScanner {
    state: NonceScannerState,
    digits: Vec<u8>,
    found: Option<String>,
}

impl NonceScanner {
    pub(super) fn new() -> Self {
        Self {
            state: NonceScannerState::Searching,
            digits: Vec::with_capacity(NONCE_HEX_LENGTH),
            found: None,
        }
    }

    pub(super) fn found(&self) -> bool {
        self.found.is_some()
    }

    pub(super) fn nonce(&self) -> String {
        self.found.clone().unwrap_or_default()
    }

    #[cfg(test)]
    pub(super) fn found_nonce(&self) -> Option<String> {
        self.found.clone()
    }

    fn reset(&mut self) {
        self.state = NonceScannerState::Searching;
        self.digits.clear();
    }

    fn reset_and_maybe_start(&mut self, b: u8) {
        self.reset();
        if b == b'[' {
            self.state = NonceScannerState::OpenBracket;
        }
    }

    fn scan_byte(&mut self, b: u8) {
        if self.found.is_some() {
            return;
        }

        match self.state {
            NonceScannerState::Searching => {
                if b == b'[' {
                    self.state = NonceScannerState::OpenBracket;
                }
            }
            NonceScannerState::OpenBracket => {
                if b.eq_ignore_ascii_case(&b'M') {
                    self.state = NonceScannerState::M;
                } else if b == b'[' {
                    self.state = NonceScannerState::OpenBracket;
                } else {
                    self.state = NonceScannerState::Searching;
                }
            }
            NonceScannerState::M => {
                if b.eq_ignore_ascii_case(&b'A') {
                    self.state = NonceScannerState::Ma;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            NonceScannerState::Ma => {
                if b.eq_ignore_ascii_case(&b'P') {
                    self.state = NonceScannerState::Map;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            NonceScannerState::Map => {
                if b.eq_ignore_ascii_case(&b'A') {
                    self.state = NonceScannerState::Mapa;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            NonceScannerState::Mapa => {
                if b.eq_ignore_ascii_case(&b'E') {
                    self.state = NonceScannerState::Mapae;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            NonceScannerState::Mapae => {
                if b == b':' {
                    self.state = NonceScannerState::HexDigits;
                    self.digits.clear();
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            NonceScannerState::HexDigits => match b {
                b']' => {
                    if self.digits.len() == NONCE_HEX_LENGTH {
                        self.found = Some(String::from_utf8_lossy(&self.digits).into_owned());
                    }
                    self.reset();
                }
                b' ' | b'\r' | b'\n' | b'\t' => self.reset(),
                b if b.is_ascii_hexdigit() => {
                    if self.digits.len() >= NONCE_HEX_LENGTH {
                        self.reset();
                        return;
                    }
                    self.digits.push(b);
                }
                _ => self.reset_and_maybe_start(b),
            },
        }
    }

    pub(super) fn scan(&mut self, data: &[u8]) {
        for &b in data {
            self.scan_byte(b);
            if self.found() {
                return;
            }
        }
    }
}

pub(super) fn is_valid_nonce(value: &str) -> bool {
    value.len() == NONCE_HEX_LENGTH && value.chars().all(|c| c.is_ascii_hexdigit())
}
