//! Bounded request correlation on authenticated, instance-fenced worker links.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use kata_transport::supervisor::{WorkerPoolSupervisor, WorkerRecoveryPeer};
use kata_types::error::{KataError, KataResult};
use kata_types::recovery::{
    MAX_RECOVERY_CHUNK_BYTES, MAX_RECOVERY_DATABASE_BYTES, MAX_RECOVERY_HOLD_MS, RecoveryCommand,
    RecoveryReply, RecoveryRequest,
};
use parking_lot::Mutex;
use tokio::sync::oneshot;
use tokio::time::Instant;
use ulid::Ulid;

const MAX_PENDING_PEERS: usize = 4096;

struct Pending {
    id: Ulid,
    command: RecoveryCommand,
    deadline: Instant,
    sender: oneshot::Sender<KataResult<RecoveryReply>>,
}

pub struct RecoveryExchange {
    supervisor: Arc<WorkerPoolSupervisor>,
    pending: Mutex<HashMap<Ulid, Pending>>,
}

impl RecoveryExchange {
    pub fn new(supervisor: Arc<WorkerPoolSupervisor>) -> Arc<Self> {
        Arc::new(Self {
            supervisor,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Sole receive owner for an offline, authenticated control-only session.
    /// It never constructs a dispatcher or applies ordinary execution frames.
    /// The caller owns this future and its shutdown budget; cancellation drops
    /// the guard, unregisters this exact peer and fails its pending request.
    pub async fn run_control_peer(&self, peer: WorkerRecoveryPeer) -> KataResult<()> {
        let _guard = ControlPeerGuard {
            exchange: self,
            peer: &peer,
        };
        let transport = peer.result_transport();
        loop {
            if !self.supervisor.recovery_peer_is_current(&peer) {
                return Err(refusal(
                    "control-only recovery peer was replaced or disconnected",
                ));
            }
            match transport.recv().await? {
                kata_transport::types::WorkerMessage::Recovery(reply) => {
                    self.accept(&peer, reply)?;
                }
                kata_transport::types::WorkerMessage::Heartbeat(_) => {}
                _ => {
                    return Err(refusal(
                        "non-recovery frame on a control-only recovery session",
                    ));
                }
            }
        }
    }

    /// Register before sending so a fast worker reply cannot precede its waiter.
    /// A dropped or timed-out caller removes its pending slot. Worker lease
    /// release is the capture coordinator's obligation, with expiry as the bound.
    /// Every Begin attempt must use a fresh nonce; retrying an expired Begin
    /// with the same tuple would make its late Ready indistinguishable. Subsequent
    /// operations retain that request tuple and bind the returned generation.
    pub async fn request(
        &self,
        peer: &WorkerRecoveryPeer,
        command: RecoveryCommand,
        budget: Duration,
    ) -> KataResult<RecoveryReply> {
        if budget.is_zero()
            || budget > Duration::from_millis(MAX_RECOVERY_HOLD_MS)
            || command.request().domain != *peer.domain()
            || !self.supervisor.recovery_peer_is_current(peer)
        {
            return Err(refusal("invalid recovery request budget or peer"));
        }
        validate_command(&command)?;
        let (sender, receiver) = oneshot::channel();
        let id = Ulid::new();
        {
            let mut pending = self.pending.lock();
            pending.retain(|_, slot| slot.deadline > Instant::now() && !slot.sender.is_closed());
            if pending.len() >= MAX_PENDING_PEERS || pending.contains_key(&peer.registration_id()) {
                return Err(refusal(
                    "recovery request already pending or exchange capacity exhausted",
                ));
            }
            pending.insert(
                peer.registration_id(),
                Pending {
                    id,
                    command: command.clone(),
                    deadline: Instant::now() + budget,
                    sender,
                },
            );
        }
        let _guard = PendingGuard {
            exchange: self,
            registration: peer.registration_id(),
            id,
        };
        tokio::time::timeout(budget, async {
            self.supervisor.send_recovery_control(peer, command).await?;
            receiver
                .await
                .map_err(|_| refusal("recovery peer disconnected or request expired"))?
        })
        .await
        .map_err(|_| KataError::Timeout("worker recovery reply deadline expired".into()))?
    }

    /// Called only by the reactor carrying the peer minted for its own transport.
    pub(crate) fn accept(&self, peer: &WorkerRecoveryPeer, reply: RecoveryReply) -> KataResult<()> {
        if !self.supervisor.recovery_peer_is_current(peer) {
            self.disconnected(peer);
            return Err(refusal(
                "recovery reply came from a disconnected or replaced registration",
            ));
        }
        let mut pending = self.pending.lock();
        let slot = pending
            .get(&peer.registration_id())
            .ok_or_else(|| refusal("unsolicited recovery reply"))?;
        if slot.deadline <= Instant::now() || !reply_matches(&slot.command, &reply) {
            return Err(refusal("stale or mismatched recovery reply"));
        }
        let slot = pending
            .remove(&peer.registration_id())
            .expect("validated pending request is held under lock");
        slot.sender
            .send(Ok(reply))
            .map_err(|_| refusal("recovery caller no longer accepts replies"))
    }

    pub(crate) fn disconnected(&self, peer: &WorkerRecoveryPeer) {
        if let Some(slot) = self.pending.lock().remove(&peer.registration_id()) {
            let _ = slot.sender.send(Err(refusal(
                "recovery transport disconnected or was replaced",
            )));
        }
    }
}

struct ControlPeerGuard<'a> {
    exchange: &'a RecoveryExchange,
    peer: &'a WorkerRecoveryPeer,
}
impl Drop for ControlPeerGuard<'_> {
    fn drop(&mut self) {
        self.exchange.supervisor.unregister_recovery_peer(self.peer);
        self.exchange.disconnected(self.peer);
    }
}

struct PendingGuard<'a> {
    exchange: &'a RecoveryExchange,
    registration: Ulid,
    id: Ulid,
}
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let mut pending = self.exchange.pending.lock();
        if pending
            .get(&self.registration)
            .is_some_and(|slot| slot.id == self.id)
        {
            pending.remove(&self.registration);
        }
    }
}

fn refusal(message: &str) -> KataError {
    KataError::Validation(message.into())
}

fn validate_command(command: &RecoveryCommand) -> KataResult<()> {
    let valid = match command {
        RecoveryCommand::Begin {
            hold_ms, max_bytes, ..
        } => {
            *hold_ms > 0
                && *hold_ms <= MAX_RECOVERY_HOLD_MS
                && *max_bytes > 0
                && *max_bytes <= MAX_RECOVERY_DATABASE_BYTES
        }
        RecoveryCommand::Read { max_bytes, .. } => {
            *max_bytes > 0 && *max_bytes <= MAX_RECOVERY_CHUNK_BYTES
        }
        RecoveryCommand::Renew { hold_ms, .. } => *hold_ms > 0 && *hold_ms <= MAX_RECOVERY_HOLD_MS,
        RecoveryCommand::Release { .. } => true,
    };
    if valid {
        Ok(())
    } else {
        Err(refusal("invalid recovery command bounds"))
    }
}

fn reply_request(reply: &RecoveryReply) -> RecoveryRequest {
    match reply {
        RecoveryReply::Ready { receipt, .. } => RecoveryRequest {
            artifact_id: receipt.artifact_id,
            request_nonce: receipt.request_nonce,
            domain: receipt.domain.clone(),
        },
        RecoveryReply::Chunk { request, .. }
        | RecoveryReply::Renewed { request, .. }
        | RecoveryReply::Released { request, .. }
        | RecoveryReply::Refused { request, .. } => request.clone(),
    }
}

fn reply_matches(command: &RecoveryCommand, reply: &RecoveryReply) -> bool {
    if command.request() != &reply_request(reply) {
        return false;
    }
    match (command, reply) {
        (_, RecoveryReply::Refused { .. }) => true,
        (RecoveryCommand::Begin { max_bytes, .. }, RecoveryReply::Ready { receipt, .. }) => {
            receipt.database_byte_len > 0
                && receipt.database_byte_len <= *max_bytes
                && receipt.database_digest.len() == 64
                && receipt
                    .database_digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        (
            RecoveryCommand::Read {
                generation_id,
                offset,
                max_bytes,
                ..
            },
            RecoveryReply::Chunk {
                generation_id: actual,
                offset: actual_offset,
                bytes,
                ..
            },
        ) => {
            generation_id == actual
                && offset == actual_offset
                && !bytes.is_empty()
                && bytes.len() <= *max_bytes as usize
        }
        (
            RecoveryCommand::Renew { generation_id, .. },
            RecoveryReply::Renewed {
                generation_id: actual,
                ..
            },
        )
        | (
            RecoveryCommand::Release { generation_id, .. },
            RecoveryReply::Released {
                generation_id: actual,
                ..
            },
        ) => generation_id == actual,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::Dispatcher;
    use crate::reactor::ResultReactor;
    use kata_core::InFlightLedger;
    use kata_transport::heartbeat::HeartbeatMonitor;
    use kata_transport::types::{WorkerControl, WorkerMessage};
    use kata_transport::{InProcessTransport, WorkerTransport};
    use kata_types::containment_claim::ClaimedContainment;
    use kata_types::identity::{WorkerEffectDomain, WorkerMembraneId};
    use kata_types::recovery::WorkerRecoveryReceipt;

    struct Rig {
        supervisor: Arc<WorkerPoolSupervisor>,
        exchange: Arc<RecoveryExchange>,
        peer: WorkerRecoveryPeer,
        worker: InProcessTransport,
        reactor: tokio::task::JoinHandle<()>,
    }
    impl Rig {
        fn new() -> Self {
            let supervisor = Arc::new(WorkerPoolSupervisor::new());
            let (main, worker) = InProcessTransport::pair(16);
            let main: Arc<dyn WorkerTransport> = Arc::new(main);
            let domain = WorkerEffectDomain {
                source_main: "source-main".into(),
                membrane: WorkerMembraneId(Ulid::new()),
                enrollment: Ulid::new(),
            };
            let peer = supervisor.register_worker_with_effect_domain(
                "worker".into(),
                Arc::clone(&main),
                vec![],
                ClaimedContainment::unstated_no_handshake(),
                *crate::test_harness::oci_rig_executor_term().digest(),
                domain,
            );
            let exchange = RecoveryExchange::new(Arc::clone(&supervisor));
            let heartbeat = Arc::new(HeartbeatMonitor::new(
                Duration::from_secs(1),
                Duration::from_secs(3),
            ));
            let ledger = InFlightLedger::in_memory();
            let dispatcher = Arc::new(Dispatcher::new(
                Arc::clone(&supervisor),
                Arc::clone(&heartbeat),
                Arc::clone(&ledger),
            ));
            let reactor = ResultReactor::new("worker".into(), main, dispatcher, heartbeat)
                .with_recovery_peer(peer.clone(), Arc::clone(&exchange))
                .spawn();
            Self {
                supervisor,
                exchange,
                peer,
                worker,
                reactor,
            }
        }
        fn begin(&self) -> RecoveryCommand {
            RecoveryCommand::Begin {
                request: RecoveryRequest {
                    artifact_id: Ulid::new(),
                    request_nonce: Ulid::new(),
                    domain: self.peer.domain().clone(),
                },
                hold_ms: 1000,
                max_bytes: 1024 * 1024,
            }
        }
        fn request(
            &self,
            command: RecoveryCommand,
            budget: Duration,
        ) -> tokio::task::JoinHandle<KataResult<RecoveryReply>> {
            let exchange = Arc::clone(&self.exchange);
            let peer = self.peer.clone();
            tokio::spawn(async move { exchange.request(&peer, command, budget).await })
        }
    }
    impl Drop for Rig {
        fn drop(&mut self) {
            self.reactor.abort();
        }
    }

    fn ready(request: &RecoveryRequest) -> RecoveryReply {
        RecoveryReply::Ready {
            receipt: WorkerRecoveryReceipt {
                artifact_id: request.artifact_id,
                request_nonce: request.request_nonce,
                domain: request.domain.clone(),
                generation_id: Ulid::new(),
                schema_version: kata_core::idempotency_store::IDEMPOTENCY_SCHEMA_VERSION,
                database_digest: "a".repeat(64),
                database_byte_len: 4096,
            },
        }
    }

    #[tokio::test]
    async fn recovery_reactor_rejects_wrong_nonce_before_delivering_the_matching_receipt() {
        let rig = Rig::new();
        let command = rig.begin();
        let expected = command.request().clone();
        let waiter = rig.request(command.clone(), Duration::from_secs(2));
        assert_eq!(
            rig.worker.recv_control().await.unwrap(),
            WorkerControl::Recovery(command)
        );
        let mut wrong = expected.clone();
        wrong.request_nonce = Ulid::new();
        rig.worker
            .send_result(WorkerMessage::Recovery(ready(&wrong)))
            .await
            .unwrap();
        let correct = ready(&expected);
        rig.worker
            .send_result(WorkerMessage::Recovery(correct.clone()))
            .await
            .unwrap();
        assert_eq!(
            waiter.await.unwrap().unwrap(),
            correct,
            "the real reactor must correlate before delivering a worker receipt"
        );
        assert!(rig.exchange.pending.lock().is_empty());
    }

    #[tokio::test]
    async fn recovery_request_timeout_and_cancellation_remove_pending_slots() {
        let rig = Rig::new();
        let command = rig.begin();
        let late = ready(command.request());
        let waiter = rig.request(command, Duration::from_millis(30));
        rig.worker.recv_control().await.unwrap();
        assert!(matches!(waiter.await.unwrap(), Err(KataError::Timeout(_))));
        assert!(rig.exchange.pending.lock().is_empty());
        assert!(rig.exchange.accept(&rig.peer, late).is_err());
        let waiter = rig.request(rig.begin(), Duration::from_secs(2));
        rig.worker.recv_control().await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(rig.exchange.pending.lock().is_empty());
    }

    #[tokio::test]
    async fn recovery_old_registration_cannot_supply_a_replacement_receipt() {
        let rig = Rig::new();
        let command = rig.begin();
        let reply = ready(command.request());
        let waiter = rig.request(command, Duration::from_secs(2));
        rig.worker.recv_control().await.unwrap();
        let (replacement, _worker) = InProcessTransport::pair(16);
        let replacement_peer = rig.supervisor.register_worker_with_effect_domain(
            "worker".into(),
            Arc::new(replacement),
            vec![],
            ClaimedContainment::unstated_no_handshake(),
            *crate::test_harness::oci_rig_executor_term().digest(),
            rig.peer.domain().clone(),
        );
        assert_ne!(
            replacement_peer.registration_id(),
            rig.peer.registration_id()
        );
        rig.worker
            .send_result(WorkerMessage::Recovery(reply))
            .await
            .unwrap();
        assert!(waiter.await.unwrap().is_err());
        assert!(rig.exchange.pending.lock().is_empty());
        assert!(
            rig.supervisor
                .send_recovery_control(&rig.peer, rig.begin())
                .await
                .is_err()
        );
    }

    #[test]
    fn recovery_chunks_bind_generation_offset_and_requested_size() {
        let request = RecoveryRequest {
            artifact_id: Ulid::new(),
            request_nonce: Ulid::new(),
            domain: WorkerEffectDomain {
                source_main: "main".into(),
                membrane: WorkerMembraneId(Ulid::new()),
                enrollment: Ulid::new(),
            },
        };
        let generation_id = Ulid::new();
        let command = RecoveryCommand::Read {
            request: request.clone(),
            generation_id,
            offset: 7,
            max_bytes: 2,
        };
        let chunk = |generation_id, offset, bytes| RecoveryReply::Chunk {
            request: request.clone(),
            generation_id,
            offset,
            bytes,
        };
        assert!(reply_matches(
            &command,
            &chunk(generation_id, 7, vec![1, 2])
        ));
        assert!(!reply_matches(&command, &chunk(Ulid::new(), 7, vec![1, 2])));
        assert!(!reply_matches(
            &command,
            &chunk(generation_id, 8, vec![1, 2])
        ));
        assert!(!reply_matches(
            &command,
            &chunk(generation_id, 7, vec![1, 2, 3])
        ));
        assert!(!reply_matches(&command, &chunk(generation_id, 7, vec![])));
    }

    #[tokio::test]
    async fn recovery_control_only_receiver_refuses_execution_frames_and_cancels_waiter() {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let (main, worker) = InProcessTransport::pair(8);
        let peer = supervisor.register_worker_with_effect_domain(
            "worker".into(),
            Arc::new(main),
            vec![],
            ClaimedContainment::unstated_no_handshake(),
            *crate::test_harness::oci_rig_executor_term().digest(),
            WorkerEffectDomain {
                source_main: "main".into(),
                membrane: WorkerMembraneId(Ulid::new()),
                enrollment: Ulid::new(),
            },
        );
        let exchange = RecoveryExchange::new(supervisor);
        let command = RecoveryCommand::Begin {
            request: RecoveryRequest {
                artifact_id: Ulid::new(),
                request_nonce: Ulid::new(),
                domain: peer.domain().clone(),
            },
            hold_ms: 1000,
            max_bytes: 1024 * 1024,
        };
        let receiver_exchange = Arc::clone(&exchange);
        let receiver_peer = peer.clone();
        let receiver =
            tokio::spawn(async move { receiver_exchange.run_control_peer(receiver_peer).await });
        let request_exchange = Arc::clone(&exchange);
        let observed_peer = peer.clone();
        let waiter = tokio::spawn(async move {
            request_exchange
                .request(&peer, command, Duration::from_secs(2))
                .await
        });
        worker.recv_control().await.unwrap();
        worker
            .send_result(WorkerMessage::Checkpoint(
                kata_transport::types::StageCheckpoint {
                    assignment_id: Ulid::new(),
                    stage_name: "fixture".into(),
                    output: serde_json::Value::Null,
                    sequence: 0,
                    fence: kata_transport::types::AttemptFence::default(),
                },
            ))
            .await
            .unwrap();
        assert!(receiver.await.unwrap().is_err());
        assert!(waiter.await.unwrap().is_err());
        assert!(exchange.pending.lock().is_empty());
        assert!(
            !exchange.supervisor.recovery_peer_is_current(&observed_peer),
            "a terminated control receiver cannot remain a healthy recovery peer"
        );
    }

    #[tokio::test]
    async fn recovery_control_receiver_cancellation_preserves_same_domain_replacement() {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let (main, _worker) = InProcessTransport::pair(8);
        let domain = WorkerEffectDomain {
            source_main: "main".into(),
            membrane: WorkerMembraneId(Ulid::new()),
            enrollment: Ulid::new(),
        };
        let register = |transport| {
            supervisor.register_worker_with_effect_domain(
                "worker".into(),
                Arc::new(transport),
                vec![],
                ClaimedContainment::unstated_no_handshake(),
                *crate::test_harness::oci_rig_executor_term().digest(),
                domain.clone(),
            )
        };
        let peer = register(main);
        let exchange = RecoveryExchange::new(Arc::clone(&supervisor));
        let mut receiver = Box::pin(exchange.run_control_peer(peer.clone()));
        // Poll the receive owner once so cancellation drops an installed guard.
        tokio::select! {
            biased;
            result = &mut receiver => panic!("receiver exited before cancellation: {result:?}"),
            () = std::future::ready(()) => {}
        }
        let (main, worker) = InProcessTransport::pair(8);
        let replacement = register(main);
        drop(receiver);
        assert!(!supervisor.recovery_peer_is_current(&peer));
        assert!(supervisor.recovery_peer_is_current(&replacement));
        assert_eq!(supervisor.worker_count(), 1);
        let command = RecoveryCommand::Begin {
            request: RecoveryRequest {
                artifact_id: Ulid::new(),
                request_nonce: Ulid::new(),
                domain,
            },
            hold_ms: 1000,
            max_bytes: 1024,
        };
        supervisor
            .send_recovery_control(&replacement, command.clone())
            .await
            .unwrap();
        assert_eq!(
            worker.recv_control().await.unwrap(),
            WorkerControl::Recovery(command)
        );
    }

    #[tokio::test]
    async fn recovery_control_receiver_cancellation_unregisters_current_peer() {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let (main, _worker) = InProcessTransport::pair(8);
        let peer = supervisor.register_worker_with_effect_domain(
            "worker".into(),
            Arc::new(main),
            vec![],
            ClaimedContainment::unstated_no_handshake(),
            *crate::test_harness::oci_rig_executor_term().digest(),
            WorkerEffectDomain {
                source_main: "main".into(),
                membrane: WorkerMembraneId(Ulid::new()),
                enrollment: Ulid::new(),
            },
        );
        let exchange = RecoveryExchange::new(Arc::clone(&supervisor));
        let mut receiver = Box::pin(exchange.run_control_peer(peer.clone()));
        tokio::select! {
            biased;
            result = &mut receiver => panic!("receiver exited before cancellation: {result:?}"),
            () = std::future::ready(()) => {}
        }
        drop(receiver);
        assert!(!supervisor.recovery_peer_is_current(&peer));
        assert!(supervisor.recovery_peers().is_empty());
        assert_eq!(supervisor.worker_count(), 0);
    }
}
