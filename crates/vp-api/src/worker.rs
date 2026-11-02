use crate::error::ApiError;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::{sync::Notify, task::JoinHandle};
use vp_product_control::{CancellationToken, ControlService, Operation};
use vp_product_domain::OperationId;

/// Owned single worker. Durable queued work is scanned, so losing an HTTP reply
/// or Notify never loses accepted operations. Startup recovery happens before this starts.
pub struct OperationWorker {
    control: Arc<ControlService>,
    tokens: Mutex<BTreeMap<OperationId, CancellationToken>>,
    notify: Notify,
    stopping: AtomicBool,
    failed: AtomicBool,
    stopped: Notify,
}
impl OperationWorker {
    pub fn start(control: Arc<ControlService>) -> (Arc<Self>, JoinHandle<()>) {
        let worker = Arc::new(Self {
            control,
            tokens: Mutex::new(BTreeMap::new()),
            notify: Notify::new(),
            stopping: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            stopped: Notify::new(),
        });
        let owned = worker.clone();
        let handle = tokio::spawn(async move { owned.run().await });
        (worker, handle)
    }
    pub fn notify(&self) {
        self.notify.notify_one();
    }
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        if let Ok(tokens) = self.tokens.lock() {
            for token in tokens.values() {
                token.cancel();
            }
        }
        self.notify();
        self.stopped.notify_one();
    }
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.stop();
    }
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub async fn stopped(&self) {
        while !self.stopping.load(Ordering::Acquire) {
            self.stopped.notified().await;
        }
    }
    async fn run(self: Arc<Self>) {
        while !self.stopping.load(Ordering::Acquire) {
            let control = self.control.clone();
            let pending = tokio::task::spawn_blocking(move || control.queued_operations()).await;
            let Ok(Ok(pending)) = pending else {
                // Unknown persistence outcome: no retry of external actions. Block
                // this worker; restart runs recovery before accepting new writes.
                self.fail();
                return;
            };
            for id in pending {
                if self.stopping.load(Ordering::Acquire) {
                    break;
                }
                let token = CancellationToken::default();
                {
                    let Ok(mut registry) = self.tokens.lock() else {
                        self.fail();
                        return;
                    };
                    registry.insert(id.clone(), token.clone());
                }
                let control = self.control.clone();
                let operation = id.clone();
                let result =
                    tokio::task::spawn_blocking(move || control.run(&operation, &token)).await;
                if let Ok(mut registry) = self.tokens.lock() {
                    registry.remove(&id);
                }
                if !matches!(result, Ok(Ok(_))) {
                    self.fail();
                    return;
                }
            }
            tokio::select! { _ = self.notify.notified() => {}, _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {} }
        }
    }
    pub fn accepting(&self) -> bool {
        !self.stopping.load(Ordering::Acquire)
    }
    pub async fn cancel(
        &self,
        request: vp_product_control::CancelRequest,
    ) -> Result<
        (
            Operation,
            vp_product_domain::Revision,
            vp_product_domain::Revision,
        ),
        ApiError,
    > {
        let control = self.control.clone();
        tokio::task::spawn_blocking(move || control.cancel_request(request))
            .await
            .map_err(|_| ApiError::internal())?
            .map_err(Into::into)
    }
}
