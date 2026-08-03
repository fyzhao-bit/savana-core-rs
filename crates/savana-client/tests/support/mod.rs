#![allow(dead_code)]

pub mod task5;

use std::collections::VecDeque;
use std::sync::Mutex;

use savana_client::{BrowserRequest, BrowserResponse, BrowserTransport, SavanaError};

#[derive(Default)]
pub struct ScriptedTransport {
    requests: Mutex<Vec<BrowserRequest>>,
    responses: Mutex<VecDeque<Result<BrowserResponse, SavanaError>>>,
}

impl ScriptedTransport {
    pub fn new(responses: Vec<Result<BrowserResponse, SavanaError>>) -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        }
    }

    pub fn take_requests(&self) -> Vec<BrowserRequest> {
        std::mem::take(&mut *self.requests.lock().expect("request lock poisoned"))
    }
}

impl BrowserTransport for ScriptedTransport {
    fn send(&self, request: BrowserRequest) -> Result<BrowserResponse, SavanaError> {
        self.requests
            .lock()
            .map_err(|_| SavanaError::transport())?
            .push(request);
        self.responses
            .lock()
            .map_err(|_| SavanaError::transport())?
            .pop_front()
            .unwrap_or_else(|| Err(SavanaError::transport()))
    }
}
