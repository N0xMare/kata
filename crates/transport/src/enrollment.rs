//! Mutual possession proof for the provisioned local-worker credential.
//! This authenticates credential holders, not an asymmetric main identity.
use crate::{
    WorkerSideTransport, WorkerTransport,
    types::{WorkerControl, WorkerMessage},
};
use kata_types::{
    error::{KataError, KataResult},
    execution_platform::ExecutorTerm,
    identity::{WorkerEffectDomain, WorkerMembraneId},
    primitives::ContentHash,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const VERSION: u32 = 2;
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_INFO_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentProbe {
    pub version: u32,
    pub worker_nonce: [u8; 32],
    pub membrane: WorkerMembraneId,
    /// The digest of the WORKER build's own executor term
    /// (`kata_worker::executor_term::node_executor_term`): the fence that worker
    /// runs every capsule under. REQUIRED, with no serde default, so a probe that
    /// does not state it does not decode and the worker is never enrolled; covered
    /// by every proof, like the rest of the probe.
    pub executor_term: ContentHash,
    pub worker_info: serde_json::Value,
}

/// What [`authenticate_worker`] establishes from the main that enrolled it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerEnrollment {
    pub domain: WorkerEffectDomain,
    /// The period this worker sends its heartbeat at: derived from the main's
    /// `heartbeat_interval_ms` (bound into [`EnrollmentControl::Bound`]) by
    /// [`crate::heartbeat::worker_send_period`], so the main's liveness deadline
    /// is measured against a cadence the main chose.
    pub heartbeat_period: Duration,
}

/// What [`authenticate_main`] establishes about the worker it enrolled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolledWorker {
    pub domain: WorkerEffectDomain,
    /// The executor term the worker's probe stated — see
    /// [`EnrollmentProbe::executor_term`].
    pub executor_term: ContentHash,
    pub worker_info: serde_json::Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentChallenge {
    pub version: u32,
    pub worker_nonce: [u8; 32],
    pub main_nonce: [u8; 32],
    pub source_main: String,
    pub proof: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentControl {
    Challenge(EnrollmentChallenge),
    Bound {
        domain: WorkerEffectDomain,
        /// The main's `[workers] heartbeat_interval_ms`, covered by `proof`. The
        /// worker heartbeats at [`crate::heartbeat::worker_send_period`] of it;
        /// zero is refused.
        heartbeat_interval_ms: u64,
        proof: [u8; 32],
    },
}

/// What the main's `main-domain-binding` proof covers beyond the probe and the
/// challenge.
#[derive(Clone, Copy, Debug)]
struct Binding<'a> {
    domain: &'a WorkerEffectDomain,
    heartbeat_interval_ms: u64,
}

fn refusal() -> KataError {
    KataError::Network("local worker mutual enrollment authentication refused".into())
}
fn nonce() -> [u8; 32] {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}
fn mac(
    secret: &str,
    role: &str,
    probe: &EnrollmentProbe,
    challenge: &EnrollmentChallenge,
    binding: Option<Binding<'_>>,
) -> KataResult<[u8; 32]> {
    if secret.is_empty() || secret.len() > 4096 {
        return Err(refusal());
    }
    let key = blake3::derive_key(
        "kata local worker enrollment credential key v1",
        secret.as_bytes(),
    );
    let transcript = serde_json::to_vec(&(
        "kata-local-enrollment-v1",
        role,
        probe,
        challenge.version,
        challenge.worker_nonce,
        challenge.main_nonce,
        &challenge.source_main,
        binding.map(|binding| (binding.domain, binding.heartbeat_interval_ms)),
    ))
    .map_err(|_| refusal())?;
    Ok(*blake3::keyed_hash(&key, &transcript).as_bytes())
}
fn proof_matches(expected: [u8; 32], received: [u8; 32]) -> bool {
    // blake3::Hash equality uses constant-time comparison.
    blake3::Hash::from(expected) == blake3::Hash::from(received)
}
fn validate_probe(probe: &EnrollmentProbe) -> KataResult<()> {
    if probe.version != VERSION
        || probe.worker_nonce == [0; 32]
        || probe.membrane.0 == ulid::Ulid::nil()
        || serde_json::to_vec(&probe.worker_info)
            .map_err(|_| refusal())?
            .len()
            > MAX_INFO_BYTES
    {
        return Err(refusal());
    }
    Ok(())
}

/// Verifies main possession before emitting a worker proof. Neither direction
/// ever sends the provisioned credential; old raw-secret Hello is refused.
pub async fn authenticate_worker(
    transport: &dyn WorkerSideTransport,
    secret: &str,
    membrane: WorkerMembraneId,
    executor_term: &ExecutorTerm,
    worker_info: serde_json::Value,
) -> KataResult<WorkerEnrollment> {
    let exchange = async {
        let probe = EnrollmentProbe {
            version: VERSION,
            worker_nonce: nonce(),
            membrane,
            executor_term: *executor_term.digest(),
            worker_info,
        };
        validate_probe(&probe)?;
        transport
            .send_result(WorkerMessage::EnrollmentProbe(probe.clone()))
            .await?;
        let WorkerControl::Enrollment(EnrollmentControl::Challenge(challenge)) =
            transport.recv_control().await?
        else {
            return Err(refusal());
        };
        if challenge.version != VERSION
            || challenge.worker_nonce != probe.worker_nonce
            || challenge.main_nonce == [0; 32]
            || challenge.source_main.is_empty()
            || challenge.source_main.len() > 255
            || !proof_matches(
                mac(secret, "main-challenge", &probe, &challenge, None)?,
                challenge.proof,
            )
        {
            return Err(refusal());
        }
        transport
            .send_result(WorkerMessage::EnrollmentProof {
                proof: mac(secret, "worker-response", &probe, &challenge, None)?,
            })
            .await?;
        let WorkerControl::Enrollment(EnrollmentControl::Bound {
            domain,
            heartbeat_interval_ms,
            proof,
        }) = transport.recv_control().await?
        else {
            return Err(refusal());
        };
        if domain.source_main != challenge.source_main
            || domain.membrane != membrane
            || domain.enrollment == ulid::Ulid::nil()
            || heartbeat_interval_ms == 0
            || !proof_matches(
                mac(
                    secret,
                    "main-domain-binding",
                    &probe,
                    &challenge,
                    Some(Binding {
                        domain: &domain,
                        heartbeat_interval_ms,
                    }),
                )?,
                proof,
            )
        {
            return Err(refusal());
        }
        Ok(WorkerEnrollment {
            domain,
            heartbeat_period: crate::heartbeat::worker_send_period(Duration::from_millis(
                heartbeat_interval_ms,
            )),
        })
    };
    let result = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .unwrap_or_else(|_| Err(refusal()));
    if result.is_err() {
        let _ = transport.shutdown().await;
    }
    result
}

/// Enrollment persistence occurs only AFTER worker possession is verified.
///
/// `heartbeat_interval` is this main's `[workers] heartbeat_interval_ms`, bound
/// into the enrollment so the worker heartbeats at the cadence this main's
/// deadline assumes. Zero is refused.
pub async fn authenticate_main(
    transport: &dyn WorkerTransport,
    secret: &str,
    source_main: &str,
    heartbeat_interval: Duration,
    enroll: impl FnOnce(WorkerMembraneId) -> KataResult<WorkerEffectDomain>,
) -> KataResult<EnrolledWorker> {
    let exchange = async {
        let heartbeat_interval_ms =
            u64::try_from(heartbeat_interval.as_millis()).map_err(|_| refusal())?;
        if source_main.is_empty() || source_main.len() > 255 || heartbeat_interval_ms == 0 {
            return Err(refusal());
        }
        let WorkerMessage::EnrollmentProbe(probe) = transport.recv().await? else {
            return Err(refusal());
        };
        validate_probe(&probe)?;
        let mut challenge = EnrollmentChallenge {
            version: VERSION,
            worker_nonce: probe.worker_nonce,
            main_nonce: nonce(),
            source_main: source_main.into(),
            proof: [0; 32],
        };
        challenge.proof = mac(secret, "main-challenge", &probe, &challenge, None)?;
        transport
            .send_control(WorkerControl::Enrollment(EnrollmentControl::Challenge(
                challenge.clone(),
            )))
            .await?;
        let WorkerMessage::EnrollmentProof { proof } = transport.recv().await? else {
            return Err(refusal());
        };
        if !proof_matches(
            mac(secret, "worker-response", &probe, &challenge, None)?,
            proof,
        ) {
            return Err(refusal());
        }
        let domain = enroll(probe.membrane)?;
        if domain.source_main != source_main
            || domain.membrane != probe.membrane
            || domain.enrollment == ulid::Ulid::nil()
        {
            return Err(refusal());
        }
        let proof = mac(
            secret,
            "main-domain-binding",
            &probe,
            &challenge,
            Some(Binding {
                domain: &domain,
                heartbeat_interval_ms,
            }),
        )?;
        transport
            .send_control(WorkerControl::Enrollment(EnrollmentControl::Bound {
                domain: domain.clone(),
                heartbeat_interval_ms,
                proof,
            }))
            .await?;
        Ok(EnrolledWorker {
            domain,
            executor_term: probe.executor_term,
            worker_info: probe.worker_info,
        })
    };
    let result = tokio::time::timeout(TIMEOUT, exchange)
        .await
        .unwrap_or_else(|_| Err(refusal()));
    if result.is_err() {
        let _ = transport.shutdown().await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InProcessTransport, LocalSocketTransport};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use ulid::Ulid;

    fn term() -> ExecutorTerm {
        ExecutorTerm::derive(&[("enrollment_fixture", b"executor")]).unwrap()
    }

    #[tokio::test]
    async fn real_socket_mutual_proof_binds_the_enrolled_domain() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("worker.sock");
        let listener = LocalSocketTransport::listen(&path).unwrap();
        let worker = LocalSocketTransport::connect(&path).await.unwrap();
        let main = listener.accept_next().await.unwrap();
        let membrane = WorkerMembraneId(Ulid::new());
        let domain = WorkerEffectDomain {
            source_main: "main".into(),
            membrane,
            enrollment: Ulid::new(),
        };
        let expected = domain.clone();
        let worker_term = term();
        let (main_result, worker_result) = tokio::join!(
            authenticate_main(
                &main,
                "fixture-secret",
                "main",
                Duration::from_secs(1),
                move |seen| {
                    assert_eq!(seen, membrane);
                    Ok(domain)
                }
            ),
            authenticate_worker(
                &worker,
                "fixture-secret",
                membrane,
                &worker_term,
                serde_json::json!({"capabilities": []})
            ),
        );
        let enrolled = main_result.unwrap();
        assert_eq!(enrolled.domain, expected);
        assert_eq!(
            enrolled.executor_term,
            *term().digest(),
            "the main learns the term the worker stated"
        );
        assert_eq!(
            worker_result.unwrap(),
            WorkerEnrollment {
                domain: expected,
                heartbeat_period: Duration::from_millis(500),
            },
            "the worker heartbeats at half the interval the main bound"
        );
    }

    /// One length-prefixed frame carrying `message` as a worker→main envelope,
    /// written as raw bytes — the wire a peer of any build can put on the socket.
    async fn write_raw_message(stream: &mut tokio::net::UnixStream, message: serde_json::Value) {
        let body =
            serde_json::to_vec(&serde_json::json!({"dir": "message", "payload": message})).unwrap();
        stream
            .write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&body).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// **A HELLO THAT STATES NO EXECUTOR TERM IS REFUSED** — over a real socket, the
    /// probe written as raw bytes with the `executor_term` key removed: the main
    /// enrolls nothing, answers with no challenge and closes the connection. The SAME
    /// probe with the key present is answered with a challenge, so the refusal is the
    /// missing term and not the raw framing.
    ///
    /// **Watched red:** with `#[serde(default)]` on
    /// [`EnrollmentProbe::executor_term`], the keyless probe decodes to the all-zero
    /// term and the main answers it with a challenge.
    #[tokio::test]
    async fn a_probe_that_states_no_executor_term_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("worker.sock");
        let listener = LocalSocketTransport::listen(&path).unwrap();
        for state_term in [true, false] {
            let mut raw = crate::unix_socket::connect_tokio(&path).await.unwrap();
            let main = listener.accept_next().await.unwrap();
            let enrolled = Arc::new(AtomicBool::new(false));
            let witness = Arc::clone(&enrolled);
            let main_task = tokio::spawn(async move {
                authenticate_main(
                    &main,
                    "fixture-secret",
                    "main",
                    Duration::from_secs(1),
                    move |membrane| {
                        witness.store(true, Ordering::SeqCst);
                        Ok(WorkerEffectDomain {
                            source_main: "main".into(),
                            membrane,
                            enrollment: Ulid::new(),
                        })
                    },
                )
                .await
            });
            let mut message =
                serde_json::to_value(WorkerMessage::EnrollmentProbe(EnrollmentProbe {
                    version: VERSION,
                    worker_nonce: nonce(),
                    membrane: WorkerMembraneId(Ulid::new()),
                    executor_term: *term().digest(),
                    worker_info: serde_json::json!({"capabilities": []}),
                }))
                .unwrap();
            let probe = message
                .as_object_mut()
                .and_then(|envelope| envelope.values_mut().find_map(|v| v.as_object_mut()))
                .filter(|probe| probe.contains_key("executor_term"))
                .expect("the encoded probe carries the term under its own key");
            if !state_term {
                probe.remove("executor_term");
            }
            write_raw_message(&mut raw, message).await;
            let mut answer = [0u8; 4];
            let answered = tokio::time::timeout(TIMEOUT, raw.read_exact(&mut answer))
                .await
                .expect("the main answers or closes within the enrollment timeout");
            if state_term {
                assert!(
                    answered.is_ok(),
                    "a probe stating its term is answered with a challenge"
                );
                main_task.abort();
            } else {
                assert!(
                    answered.is_err(),
                    "a probe stating no term is answered with nothing: {answered:?}"
                );
                assert!(
                    main_task.await.unwrap().is_err(),
                    "the main refuses the enrollment"
                );
                assert!(
                    !enrolled.load(Ordering::SeqCst),
                    "nothing is enrolled for it"
                );
            }
        }
    }

    #[tokio::test]
    async fn fake_main_gets_no_credential_or_worker_proof() {
        let (main, worker) = InProcessTransport::pair(8);
        let task = tokio::spawn(async move {
            authenticate_worker(
                &worker,
                "fixture-secret-never-transmitted",
                WorkerMembraneId(Ulid::new()),
                &term(),
                serde_json::json!({}),
            )
            .await
        });
        let first = main.recv().await.unwrap();
        assert!(
            !serde_json::to_string(&first)
                .unwrap()
                .contains("fixture-secret-never-transmitted")
        );
        let WorkerMessage::EnrollmentProbe(probe) = first else {
            panic!("raw credential Hello reached unauthenticated main")
        };
        main.send_control(WorkerControl::Enrollment(EnrollmentControl::Challenge(
            EnrollmentChallenge {
                version: VERSION,
                worker_nonce: probe.worker_nonce,
                main_nonce: nonce(),
                source_main: "forged-main".into(),
                proof: [0; 32],
            },
        )))
        .await
        .unwrap();
        let observed = main.recv().await;
        assert!(
            observed.is_err(),
            "unverified main must not receive a worker proof: {observed:?}"
        );
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn reflecting_main_proof_cannot_enroll_a_worker() {
        let (main, worker) = InProcessTransport::pair(8);
        let task = tokio::spawn(async move {
            authenticate_main(
                &main,
                "fixture-secret",
                "main",
                Duration::from_secs(1),
                |_| panic!("unauthenticated enrollment mutation"),
            )
            .await
        });
        let probe = EnrollmentProbe {
            version: VERSION,
            worker_nonce: nonce(),
            membrane: WorkerMembraneId(Ulid::new()),
            executor_term: *term().digest(),
            worker_info: serde_json::json!({}),
        };
        worker
            .send_result(WorkerMessage::EnrollmentProbe(probe))
            .await
            .unwrap();
        let WorkerControl::Enrollment(EnrollmentControl::Challenge(challenge)) =
            worker.recv_control().await.unwrap()
        else {
            panic!()
        };
        worker
            .send_result(WorkerMessage::EnrollmentProof {
                proof: challenge.proof,
            })
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[test]
    fn captured_legacy_hello_is_not_authentication_in_the_new_protocol() {
        let captured = r#"{"kind":"hello","data":{"secret":"fixture-secret","worker_info":{}}}"#;
        assert!(serde_json::from_str::<WorkerMessage>(captured).is_err());
    }

    #[test]
    fn proofs_bind_both_nonces_metadata_domain_and_direction() {
        let probe = EnrollmentProbe {
            version: VERSION,
            worker_nonce: nonce(),
            membrane: WorkerMembraneId(Ulid::new()),
            executor_term: *term().digest(),
            worker_info: serde_json::json!({"capabilities": []}),
        };
        let challenge = EnrollmentChallenge {
            version: VERSION,
            worker_nonce: probe.worker_nonce,
            main_nonce: nonce(),
            source_main: "main".into(),
            proof: [0; 32],
        };
        let domain = WorkerEffectDomain {
            source_main: "main".into(),
            membrane: probe.membrane,
            enrollment: Ulid::new(),
        };
        let binding = Binding {
            domain: &domain,
            heartbeat_interval_ms: 1_000,
        };
        let baseline = mac(
            "secret",
            "main-domain-binding",
            &probe,
            &challenge,
            Some(binding),
        )
        .unwrap();
        let mut changed_domain = domain.clone();
        changed_domain.enrollment = Ulid::new();
        assert_ne!(
            baseline,
            mac(
                "secret",
                "main-domain-binding",
                &probe,
                &challenge,
                Some(Binding {
                    domain: &changed_domain,
                    ..binding
                })
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            mac(
                "secret",
                "main-domain-binding",
                &probe,
                &challenge,
                Some(Binding {
                    heartbeat_interval_ms: 2_000,
                    ..binding
                })
            )
            .unwrap(),
            "the main's heartbeat interval is covered by the binding proof"
        );
        let mut changed_challenge = challenge.clone();
        changed_challenge.main_nonce = nonce();
        assert_ne!(
            baseline,
            mac(
                "secret",
                "main-domain-binding",
                &probe,
                &changed_challenge,
                Some(binding)
            )
            .unwrap()
        );
        let mut changed_probe = probe.clone();
        changed_probe.worker_nonce = nonce();
        assert_ne!(
            baseline,
            mac(
                "secret",
                "main-domain-binding",
                &changed_probe,
                &challenge,
                Some(binding)
            )
            .unwrap()
        );
        assert_ne!(
            baseline,
            mac(
                "secret",
                "worker-response",
                &probe,
                &challenge,
                Some(binding)
            )
            .unwrap()
        );
        changed_probe = probe.clone();
        changed_probe.executor_term = ContentHash::new([7; 32]);
        assert_ne!(
            baseline,
            mac(
                "secret",
                "main-domain-binding",
                &changed_probe,
                &challenge,
                Some(binding)
            )
            .unwrap(),
            "the stated executor term is covered by the proofs"
        );
        changed_probe = probe.clone();
        changed_probe.worker_info = serde_json::json!({"capabilities": ["forged"]});
        assert_ne!(
            baseline,
            mac(
                "secret",
                "main-domain-binding",
                &changed_probe,
                &challenge,
                Some(binding)
            )
            .unwrap()
        );
    }
}
