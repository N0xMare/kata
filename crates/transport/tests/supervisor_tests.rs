//! Tests for crates/transport/src/supervisor.rs. Extracted from the inline #[cfg(test)] module.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use kata_transport::types::{CheckedDispatchFrame, WorkerMessage};
use kata_transport::{InProcessTransport, WorkerPoolSupervisor, WorkerTransport};
use kata_types::KataResult;
use smol_str::SmolStr;
use ulid::Ulid;

fn test_assignment() -> kata_transport::types::CapsuleAssignment {
    let mut capsule = kata_test_utils::sample_capsule_assignment();
    capsule.attempt_id = Ulid::new();
    capsule.execution_id = Ulid::new();
    capsule
}

#[tokio::test]
async fn same_name_replacement_cannot_receive_predecessor_membrane_dispatch() {
    let supervisor = WorkerPoolSupervisor::new();
    let authority = supervisor.claim_dispatch_authority().unwrap();
    let (sender, receiver) = InProcessTransport::pair(4);
    let predecessor = kata_types::identity::WorkerEffectDomain {
        source_main: "test-main".into(),
        membrane: kata_types::identity::WorkerMembraneId(Ulid::new()),
        enrollment: Ulid::new(),
    };
    let replacement = kata_types::identity::WorkerEffectDomain {
        membrane: kata_types::identity::WorkerMembraneId(Ulid::new()),
        enrollment: Ulid::new(),
        ..predecessor.clone()
    };
    supervisor.register_worker_with_effect_domain(
        SmolStr::new("same-name"),
        Arc::new(sender),
        vec![],
        kata_types::containment_claim::ClaimedContainment::unstated_no_handshake(),
        kata_types::primitives::ContentHash::new([0x7E; 32]),
        replacement,
    );
    let counter = Arc::clone(
        &supervisor
            .get_worker("same-name")
            .unwrap()
            .active_assignments,
    );
    let mut assignment = test_assignment();
    assignment.effect_domain = Some(predecessor);
    let outcome = supervisor
        .dispatch_to_current_instance(
            &authority,
            "same-name",
            &counter,
            CheckedDispatchFrame::new(kata_transport::types::DispatchFrame::Capsule(Box::new(
                assignment,
            )))
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        kata_transport::supervisor::InstanceFencedDispatch::RegistrationReplaced
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), receiver.recv_frame())
            .await
            .is_err(),
        "replacement receiver must observe zero commands"
    );
}

struct BlockingTransport {
    entered: Arc<tokio::sync::Barrier>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait]
impl WorkerTransport for BlockingTransport {
    async fn dispatch(&self, _assignment: CheckedDispatchFrame) -> KataResult<()> {
        self.entered.wait().await;
        self.release.acquire().await.unwrap().forget();
        Ok(())
    }

    async fn recv(&self) -> KataResult<WorkerMessage> {
        std::future::pending().await
    }

    async fn shutdown(&self) -> KataResult<()> {
        Ok(())
    }

    fn is_alive(&self) -> bool {
        true
    }

    fn peer_pid(&self) -> Option<u32> {
        None
    }

    fn kind(&self) -> &'static str {
        "blocking-test"
    }
}

#[test]
fn explicit_w3c_injection_ignores_foreign_global_and_clears_stale_headers() {
    use opentelemetry::propagation::TextMapPropagator as _;
    use opentelemetry::trace::{
        SpanContext, SpanId, TraceContextExt as _, TraceFlags, TraceId, TraceState,
    };

    #[derive(Debug)]
    struct ForeignPropagator {
        fields: Vec<String>,
    }

    impl opentelemetry::propagation::TextMapPropagator for ForeignPropagator {
        fn inject_context(
            &self,
            _context: &opentelemetry::Context,
            injector: &mut dyn opentelemetry::propagation::Injector,
        ) {
            injector.set("traceparent", "foreign-global-value".to_string());
        }

        fn extract_with_context(
            &self,
            context: &opentelemetry::Context,
            _extractor: &dyn opentelemetry::propagation::Extractor,
        ) -> opentelemetry::Context {
            context.clone()
        }

        fn fields(&self) -> opentelemetry::propagation::text_map_propagator::FieldIter<'_> {
            opentelemetry::propagation::text_map_propagator::FieldIter::new(&self.fields)
        }
    }

    opentelemetry::global::set_text_map_propagator(ForeignPropagator {
        fields: vec!["traceparent".to_string()],
    });
    let expected = SpanContext::new(
        TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap(),
        SpanId::from_hex("00f067aa0ba902b7").unwrap(),
        TraceFlags::SAMPLED,
        true,
        TraceState::default(),
    );
    let context = opentelemetry::Context::new().with_remote_span_context(expected.clone());
    let mut assignment = test_assignment();
    assignment.trace.traceparent = "stale-parent".to_string();
    assignment.trace.trace_state = "stale-state".to_string();

    kata_transport::supervisor::inject_otel_context_for_test(&mut assignment, &context);
    assert_ne!(assignment.trace.traceparent, "foreign-global-value");
    assert!(
        assignment
            .trace
            .traceparent
            .starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-")
    );

    let carrier = std::collections::HashMap::from([
        (
            "traceparent".to_string(),
            assignment.trace.traceparent.clone(),
        ),
        (
            "tracestate".to_string(),
            assignment.trace.trace_state.clone(),
        ),
    ]);
    let extracted = opentelemetry_sdk::propagation::TraceContextPropagator::new().extract(&carrier);
    let extracted_span = extracted.span();
    assert_eq!(
        extracted_span.span_context().trace_id(),
        expected.trace_id()
    );
    assert_eq!(extracted_span.span_context().span_id(), expected.span_id());

    kata_transport::supervisor::inject_otel_context_for_test(
        &mut assignment,
        &opentelemetry::Context::new(),
    );
    assert!(assignment.trace.traceparent.is_empty());
    assert!(assignment.trace.trace_state.is_empty());
}

#[test]
fn register_and_dispatch() {
    kata_test_seeded::run_seeded("register_and_dispatch", |_ctx| async move {
        let supervisor = WorkerPoolSupervisor::new();
        let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
        let (home, worker) = InProcessTransport::pair(8);

        supervisor.register_worker(SmolStr::new("w1"), Arc::new(home));
        assert_eq!(supervisor.worker_count(), 1);

        let assignment = test_assignment();
        let expected_id = assignment.attempt_id;
        supervisor
            .dispatch_to(
                &dispatch_authority,
                "w1",
                kata_transport::CheckedDispatchFrame::new(
                    kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let received = capsule_frame(worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, expected_id);
    });
}

#[test]
fn instance_fence_refuses_same_id_replacement_before_transport_call() {
    kata_test_seeded::run_seeded(
        "instance_fence_refuses_same_id_replacement_before_transport_call",
        |_ctx| async move {
            let supervisor = WorkerPoolSupervisor::new();
            let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
            let (old_home, old_worker) = InProcessTransport::pair(8);
            supervisor.register_worker(SmolStr::new("same"), Arc::new(old_home));
            let old_counter =
                Arc::clone(&supervisor.get_worker("same").unwrap().active_assignments);

            let (replacement_home, replacement_worker) = InProcessTransport::pair(8);
            supervisor.register_worker(SmolStr::new("same"), Arc::new(replacement_home));
            let outcome = supervisor
                .dispatch_to_current_instance(
                    &dispatch_authority,
                    "same",
                    &old_counter,
                    kata_transport::CheckedDispatchFrame::new(
                        kata_transport::types::DispatchFrame::Capsule(Box::new(test_assignment())),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                kata_transport::supervisor::InstanceFencedDispatch::RegistrationReplaced
            ));

            drop(supervisor);
            assert!(old_worker.recv_frame().await.is_err());
            assert!(replacement_worker.recv_frame().await.is_err());
        },
    );
}

#[test]
fn pinned_instance_does_not_block_same_id_replacement_while_send_waits() {
    kata_test_seeded::run_seeded(
        "pinned_instance_does_not_block_same_id_replacement_while_send_waits",
        |_ctx| async move {
            let supervisor = Arc::new(WorkerPoolSupervisor::new());
            let authority = supervisor.claim_dispatch_authority().unwrap();
            let entered = Arc::new(tokio::sync::Barrier::new(2));
            let release = Arc::new(tokio::sync::Semaphore::new(0));
            supervisor.register_worker(
                SmolStr::new("same"),
                Arc::new(BlockingTransport {
                    entered: Arc::clone(&entered),
                    release: Arc::clone(&release),
                }),
            );
            let counter = Arc::clone(&supervisor.get_worker("same").unwrap().active_assignments);
            let send = supervisor.dispatch_to_current_instance(
                &authority,
                "same",
                &counter,
                kata_transport::CheckedDispatchFrame::new(
                    kata_transport::types::DispatchFrame::Capsule(Box::new(test_assignment())),
                )
                .unwrap(),
            );
            let replace = async {
                entered.wait().await;
                let (replacement, _worker) = InProcessTransport::pair(8);
                supervisor.register_worker(SmolStr::new("same"), Arc::new(replacement));
                release.add_permits(1);
            };
            let (outcome, ()) = futures::join!(send, replace);
            assert!(matches!(
                outcome.unwrap(),
                kata_transport::supervisor::InstanceFencedDispatch::Sent
            ));
        },
    );
}

/// `dispatch_to` — the capsule arm's delivery door — does not hold the registry across
/// its send. While a send is parked inside the transport (a peer that is not draining),
/// `unregister_worker`, the death path's registry write, completes on another thread.
///
/// **Would red if:** the shard guard lived across the `transport.dispatch(..).await`
/// again — the write blocks its thread until the send ends, and here it never would.
#[test]
fn dispatch_to_does_not_hold_the_registry_while_the_send_waits() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let supervisor = Arc::new(WorkerPoolSupervisor::new());
        let authority = supervisor.claim_dispatch_authority().unwrap();
        let entered = Arc::new(tokio::sync::Barrier::new(2));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        supervisor.register_worker(
            SmolStr::new("parked"),
            Arc::new(BlockingTransport {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
        );
        let send = tokio::spawn({
            let supervisor = Arc::clone(&supervisor);
            async move {
                supervisor
                    .dispatch_to(
                        &authority,
                        "parked",
                        kata_transport::CheckedDispatchFrame::new(
                            kata_transport::types::DispatchFrame::Capsule(Box::new(
                                test_assignment(),
                            )),
                        )
                        .unwrap(),
                    )
                    .await
            }
        });
        entered.wait().await;
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn({
            let supervisor = Arc::clone(&supervisor);
            move || {
                supervisor.unregister_worker("parked");
                let _ = done.send(());
            }
        });
        assert!(
            finished
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_ok(),
            "the registry write waited on a parked send: dispatch_to held its shard guard \
             across the await"
        );
        assert_eq!(supervisor.worker_count(), 0);
        release.add_permits(1);
        send.await
            .unwrap()
            .expect("the pinned transport still completes the send");
    });
}

#[test]
fn dispatch_to_unknown_worker_fails() {
    kata_test_seeded::run_seeded("dispatch_to_unknown_worker_fails", |_ctx| async move {
        let supervisor = WorkerPoolSupervisor::new();
        let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
        let result = supervisor
            .dispatch_to(
                &dispatch_authority,
                "missing",
                kata_transport::CheckedDispatchFrame::new(
                    kata_transport::types::DispatchFrame::Capsule(Box::new(test_assignment())),
                )
                .unwrap(),
            )
            .await;
        assert!(result.is_err());
    });
}

#[test]
fn unregister_worker() {
    kata_test_seeded::run_seeded("unregister_worker", |_ctx| async move {
        let supervisor = WorkerPoolSupervisor::new();
        let (home, _worker) = InProcessTransport::pair(8);

        supervisor.register_worker(SmolStr::new("w1"), Arc::new(home));
        assert_eq!(supervisor.worker_count(), 1);

        supervisor.unregister_worker("w1");
        assert_eq!(supervisor.worker_count(), 0);
    });
}

#[test]
fn dispatch_to_live_worker() {
    kata_test_seeded::run_seeded("dispatch_to_live_worker", |_ctx| async move {
        let supervisor = WorkerPoolSupervisor::new();
        let dispatch_authority = supervisor.claim_dispatch_authority().unwrap();
        let (live_home, live_worker) = InProcessTransport::pair(8);

        supervisor.register_worker(SmolStr::new("live"), Arc::new(live_home));

        let assignment = test_assignment();
        let expected_id = assignment.attempt_id;
        supervisor
            .dispatch_to(
                &dispatch_authority,
                "live",
                kata_transport::CheckedDispatchFrame::new(
                    kata_transport::types::DispatchFrame::Capsule(Box::new(assignment)),
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let received = capsule_frame(live_worker.recv_frame().await.unwrap());
        assert_eq!(received.attempt_id, expected_id);
    });
}

#[test]
fn multi_worker_inventory_is_sorted_and_normalized() {
    kata_test_seeded::run_seeded(
        "multi_worker_inventory_is_sorted_and_normalized",
        |_ctx| async move {
            let supervisor = WorkerPoolSupervisor::new();
            let (z_home, _z_worker) = InProcessTransport::pair(8);
            let (a_home, _a_worker) = InProcessTransport::pair(8);

            supervisor.register_worker_with_caps(
                SmolStr::new("z-worker"),
                Arc::new(z_home),
                vec!["shell".to_string(), "agent:codex".to_string()],
            );
            supervisor.register_worker_with_caps(
                SmolStr::new("a-worker"),
                Arc::new(a_home),
                vec![
                    "shell".to_string(),
                    "agent:codex".to_string(),
                    "shell".to_string(),
                ],
            );
            supervisor
                .get_worker("a-worker")
                .unwrap()
                .active_assignments
                .store(3, Ordering::Relaxed);

            let inventory = supervisor.worker_inventory();
            assert_eq!(
                inventory.iter().map(|w| w.id.as_str()).collect::<Vec<_>>(),
                vec!["a-worker", "z-worker"]
            );
            assert_eq!(
                inventory[0].capabilities,
                vec!["agent:codex".to_string(), "shell".to_string()]
            );
            assert_eq!(inventory[0].transport, "in_process");
            assert!(inventory[0].alive);
            assert_eq!(inventory[0].active_assignment_count, 3);
        },
    );
}

#[test]
fn worker_inventory_includes_registered_dead_worker_liveness() {
    kata_test_seeded::run_seeded(
        "worker_inventory_includes_registered_dead_worker_liveness",
        |_ctx| async move {
            let supervisor = WorkerPoolSupervisor::new();
            let (home, _worker) = InProcessTransport::pair(8);
            let home = Arc::new(home);
            supervisor.register_worker(SmolStr::new("w1"), home.clone());

            home.shutdown().await.unwrap();

            let inventory = supervisor.worker_inventory();
            assert_eq!(inventory.len(), 1);
            assert_eq!(inventory[0].id, "w1");
            assert!(!inventory[0].alive);
        },
    );
}

/// `send_control_to` reaches the named worker's transport, and REFUSES
/// rather than silently succeeding when it cannot.
///
/// # Why the refusal half is the important half
///
/// This is the hop `WorkflowExecutor::cancel` depends on. If an unregistered or
/// dead worker answered `Ok(())`, cancel would report that it stopped a stage it
/// never reached — telling an operator the work ended while it is still running
/// and still spending. That is precisely the failure a stop-ack exists to
/// prevent, and it would be invisible: the operator sees success either way.
///
/// # Counterfactual
///
/// Change either refusal in `send_control_to` to `Ok(())` and the matching
/// assertion below fails; the delivery half keeps passing, which is what makes
/// the two halves worth asserting separately.
#[kata_test_utils::kata_timeout(secs = 30)]
#[tokio::test]
async fn send_control_to_reaches_the_worker_and_refuses_when_it_cannot() {
    use kata_transport::WorkerSideTransport;
    use kata_transport::types::{AttemptFence, WorkerControl};

    let (home, worker) = InProcessTransport::pair(8);
    let home: Arc<dyn WorkerTransport> = Arc::new(home);
    let supervisor = WorkerPoolSupervisor::new();
    supervisor.register_worker(SmolStr::new("w-1"), Arc::clone(&home));

    let assignment_id = Ulid::new();
    supervisor
        .send_control_to(
            "w-1",
            WorkerControl::Stop {
                assignment_id,
                fence: AttemptFence::commanding(4, SmolStr::new("w-1")),
                reason: "operator asked".into(),
            },
        )
        .await
        .expect("a registered, live worker receives the stop");

    let got = WorkerSideTransport::recv_control(&worker)
        .await
        .expect("the worker side observes it");
    let (got_id, fence) = got.fenced_attempt().expect("stop carries an attempt fence");
    assert_eq!(got_id, assignment_id);
    assert_eq!(
        fence.lease_epoch, 4,
        "the generation the main decided on must cross intact; a stop that loses \
         its epoch is a cross-generation kill"
    );

    // An UNREGISTERED worker must be an error, never a silent success.
    let err = supervisor
        .send_control_to(
            "w-does-not-exist",
            WorkerControl::Stop {
                assignment_id,
                fence: AttemptFence::commanding(4, SmolStr::new("w-does-not-exist")),
                reason: String::new(),
            },
        )
        .await
        .expect_err("an unregistered worker must refuse, not report a delivered stop");
    assert!(
        err.to_string().contains("not registered"),
        "the refusal names the gap: {err}"
    );
}

/// A worker that has stopped draining its connection must not park the operator
/// forever, and the write must NOT be cancelled to achieve that.
///
/// Both halves are the regression, because the obvious way to bound this path
/// re-creates a worse defect than the one it closes. `local_socket`'s outbound
/// path may now park — a stop written while the assignment queue is saturated
/// waits behind those assignments in the socket, and the drain that ends the
/// park is the worker finishing stages that need not have any deadline of their
/// own. So `send_control_to` bounds the WAIT. But `write_frame` is not
/// cancel-safe: a `timeout(_, send_control(..))` that drops the send future
/// mid-frame leaves a length prefix with a partial body, the peer's decoder
/// fails, the supervisor reads that as worker death, and
/// `Dispatcher::handle_worker_death` settles every live attempt on the worker as
/// lost (PROVEN AMBIGUOUS). The bound is therefore on JOINING a spawned write.
///
/// The `!dropped` assertion is what pins the second half: swap the spawn for a
/// plain `timeout` around the send and this test reds on it rather than on the
/// deadline.
#[kata_test_utils::kata_timeout]
#[tokio::test(start_paused = true)]
async fn a_stop_to_a_worker_that_never_drains_is_bounded_without_cancelling_the_write() {
    use std::sync::atomic::AtomicBool;

    use kata_transport::types::{AttemptFence, WorkerControl, WorkerMessage};
    use kata_types::error::KataResult;

    /// Records whether the send future was ENTERED and whether it was DROPPED
    /// before completing. A cancelled write is exactly `entered && dropped`.
    #[derive(Default)]
    struct SendWitness {
        entered: AtomicBool,
        dropped: AtomicBool,
    }

    struct DropFlag(Arc<SendWitness>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct NeverDrains(Arc<SendWitness>);

    #[async_trait::async_trait]
    impl WorkerTransport for NeverDrains {
        async fn dispatch(&self, _a: kata_transport::CheckedDispatchFrame) -> KataResult<()> {
            unreachable!("not exercised")
        }
        async fn recv(&self) -> KataResult<WorkerMessage> {
            unreachable!("not exercised")
        }
        async fn send_control(&self, _control: WorkerControl) -> KataResult<()> {
            self.0.entered.store(true, Ordering::SeqCst);
            // Stands in for `write_frame` parked on a full kernel send buffer:
            // mid-frame, uncancellable without corrupting the stream.
            let _guard = DropFlag(Arc::clone(&self.0));
            std::future::pending::<()>().await;
            unreachable!("the peer never drains")
        }
        async fn shutdown(&self) -> KataResult<()> {
            Ok(())
        }
        fn is_alive(&self) -> bool {
            true
        }
        fn peer_pid(&self) -> Option<u32> {
            None
        }
        fn kind(&self) -> &'static str {
            "never_drains"
        }
    }

    let witness = Arc::new(SendWitness::default());
    let supervisor = WorkerPoolSupervisor::new();
    supervisor.register_worker(
        SmolStr::new("wedged"),
        Arc::new(NeverDrains(Arc::clone(&witness))),
    );

    let started = tokio::time::Instant::now();
    let err = supervisor
        .send_control_to(
            "wedged",
            WorkerControl::Stop {
                assignment_id: Ulid::new(),
                fence: AttemptFence::commanding(7, SmolStr::new("wedged")),
                reason: "operator cancelled".into(),
            },
        )
        .await
        .expect_err("a wedged worker must produce a typed answer, never park the operator");

    assert!(
        witness.entered.load(Ordering::SeqCst),
        "the send must actually have been attempted; a refusal before the write \
         would prove nothing about the bound"
    );
    assert!(
        !witness.dropped.load(Ordering::SeqCst),
        "the write future must NOT have been dropped: cancelling a half-written \
         frame desyncs the connection, which the supervisor reads as worker death \
         and settles the attempts being cancelled"
    );
    assert_eq!(
        started.elapsed().as_secs(),
        30,
        "the answer arrives on the declared bound, not on some other timer"
    );
    let text = err.to_string();
    assert!(
        text.starts_with("timeout:"),
        "the caller gets a TYPED answer it can distinguish from a refusal: {text}"
    );
    assert!(
        text.contains("kata run discharge-stop"),
        "the refusal must name a recourse that EXISTS: {text}"
    );
    assert!(
        text.contains("awaiting_worker_acknowledgement"),
        "and must say what the operator will see until then: {text}"
    );
}

/// Unwrap the capsule arm of a received dispatch frame — the only arm left.
#[track_caller]
fn capsule_frame(
    frame: kata_transport::types::DispatchFrame,
) -> kata_transport::types::CapsuleAssignment {
    let kata_transport::types::DispatchFrame::Capsule(capsule) = frame;
    *capsule
}
