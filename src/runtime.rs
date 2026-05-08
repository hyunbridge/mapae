use std::sync::atomic::{AtomicBool, Ordering};

/// 프로세스 전역 런타임 상태.
pub struct RuntimeState {
    draining: AtomicBool,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            draining: AtomicBool::new(false),
        }
    }

    pub fn begin_draining(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_state_tracks_draining() {
        let state = RuntimeState::new();
        assert!(!state.is_draining());

        state.begin_draining();
        assert!(state.is_draining());
    }
}
