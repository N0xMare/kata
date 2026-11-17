//! The INBOUND half of the attempt fence.
//!
//! # What this refuses, and what other mechanisms already refuse
//!
//! Four adversaries must not be able to transition the ledger. They are not all
//! this module's, and saying which are matters more than the count:
//!
//! | adversary | refused by |
//! |---|---|
//! | duplicate | the inbox fold — [`super::EventAcceptance::IdempotentAck`] |
//! | reordered | NOT EXPRESSIBLE — see below |
//! | wrong-worker | this module: the frame names its sender |
//! | stale generation | this module: the frame names its epoch |
//!
//! "Reordered" deserves the precision, because claiming it as refused would be the
//! tautological kind: an attempt-terminal stream carries exactly ONE slot per
//! generation (`event_seq = 1`), so two terminals for one generation cannot be out
//! of order. A second frame at that slot is either an idempotent ACK (same digest)
//! or a typed divergence refusal (different digest). So the honest claim is
//! that reordering has no way to be represented — not that this module refuses it.
//!
//! The two this module refuses share one requirement: fencing coordinates on the
//! frame to compare the durable row against. The durable halves are
//! `attempts.worker_id` (the placement) and `attempts.lease_epoch` (the
//! generation). This module is the INBOUND half: the worker echoes
//! `CapsuleAssignment::lease_epoch` back on `AttemptFence`, so a STALE frame from
//! generation N redelivered after the attempt has advanced to N+1 is refused
//! rather than keyed to N+1.
//!
//! # Why this runs BEFORE the inbox seam
//!
//! Main ingress authenticates and validates attempt/sender/epoch **before
//! sequence acceptance**, and records a refusal in a separate bounded
//! security-audit stream that does not consume an accepted attempt sequence. A
//! fence that ran after the seam would
//! have already advanced the attempt's slot on behalf of a frame it then refused —
//! which is the double-write the fence exists to stop.
//!
//! # Why a refused frame is not an error
//!
//! [`FrameRefusal`] is returned, not raised. A refusal is an expected, bounded
//! event: recovery legitimately produces late frames from superseded generations,
//! and killing the transport over one would turn a fenced frame into an outage.
//! The caller drops the frame, records the refusal, and keeps reading.
//!
//! # The protocol version window is closed at BOTH ends
//!
//! [`FrameRefusal::ProtocolTooNew`] is not one of the four adversaries above. A
//! version check that tested only `< MIN_FENCED_PROTOCOL_VERSION` would admit a peer
//! announcing `2`, `99` or `u16::MAX` — every value above the one number this build
//! implements — and then compare its epoch and worker id as though this build knew
//! what they meant.
//!
//! The two version refusals stay separate because they name OPPOSITE recourse:
//! [`FrameRefusal::UnfencedSender`] means upgrade the SENDER,
//! [`FrameRefusal::ProtocolTooNew`] means upgrade the MAIN. Collapsing them into
//! one "bad version" refusal would be cheaper to write and would tell half the
//! operators who read it to move the wrong side of the connection.
//!
//! What this does NOT deliver is a second, independent number. A complete version
//! window has two — a protocol number and a **certificate** number, the provider's
//! claim about what it enforces — so that a frame-shape disagreement and a
//! containment-claim disagreement are never one ambiguous refusal. Only the
//! protocol half exists here, because the protocol half is the half that has a
//! producer: `AttemptFence::protocol_version` is on the wire and any peer can set
//! it. Nothing in this build produces or consumes a certificate number, and
//! minting one would be a constant with no claimant — so the certificate half is
//! NOT enforced.

use std::fmt;

/// The fencing coordinates a worker frame CLAIMS, lifted off the wire.
///
/// A borrowed view rather than the transport type itself: `kata-core` must not
/// depend on `kata-transport` (the dependency runs the other way), and the fence
/// is a decision about three scalars, not about a frame.
///
/// Deliberately carries no `attempt_id`: the caller resolved the durable
/// placement BY that id to build [`DurablePlacement`], so passing it again would
/// be a second copy of a fact this function never reads — and a field nobody
/// reads is an advertised-but-unconsumed shape. The
/// refusal is returned to a caller that already holds the id and logs it.
#[derive(Clone, Copy, Debug)]
pub struct ClaimedFence<'a> {
    /// The fencing contract version the sender speaks. `0` means it speaks none.
    pub protocol_version: u16,
    /// The generation the sender claims to be reporting under.
    pub lease_epoch: i64,
    /// The worker the sender claims to be.
    pub worker_id: &'a str,
}

/// What the main DURABLY holds about the same attempt.
#[derive(Clone, Copy, Debug)]
pub struct DurablePlacement<'a> {
    /// `attempts.lease_epoch` — the generation currently live.
    pub lease_epoch: i64,
    /// `attempts.worker_id` — the worker this attempt is currently placed on, or
    /// `None` when it holds none (parked, released, or dispatched-but-undelivered).
    pub worker_id: Option<&'a str>,
}

/// The lowest protocol version whose fencing claims the main will act on.
///
/// Spelled here rather than imported from `kata-transport` because this crate is
/// BELOW that one. The two are pinned equal by
/// `the_core_and_transport_protocol_versions_are_one_number`, so a bump on either
/// side that forgets the other fails rather than silently splitting the contract.
pub const MIN_FENCED_PROTOCOL_VERSION: u16 = 1;

/// The highest protocol version this build IMPLEMENTS.
///
/// The ceiling of the window [`MIN_FENCED_PROTOCOL_VERSION`] floors, and a
/// different question from it, which is why the two names do not rhyme:
///
/// * the FLOOR asks *"does this sender carry fencing facts at all?"* — below it
///   the frame has no coordinates, so there is nothing to compare;
/// * the CEILING asks *"do I know what this sender's coordinates MEAN?"* — above
///   it the frame has coordinates and this build has no definition for them,
///   which is strictly worse than having none. Every fence field is
///   `#[serde(default)]`, so a frame from a protocol this build never learned
///   still decodes into a `u16`, an `i64` and a string; what it does not do is
///   arrive with the meaning those fields had when the sender wrote them.
///
/// Equal to [`MIN_FENCED_PROTOCOL_VERSION`] today because this build implements
/// exactly one version. They are two constants because they are two facts: a
/// build that learned `2` while still honouring `1`-speaking senders would move
/// the ceiling and leave the floor. Both are pinned to
/// [`kata_transport::ATTEMPT_PROTOCOL_VERSION`] by tests in this module — the
/// ceiling because the version a build ANNOUNCES is the newest it implements,
/// the floor because a build that stops honouring the version it announces
/// fences its own fleet out.
pub const MAX_SUPPORTED_PROTOCOL_VERSION: u16 = 1;

/// The fencing window may not be empty, and that is a COMPILE error rather than
/// a test.
///
/// With the floor above the ceiling every version is simultaneously too old and
/// too new, so the whole fleet is refused by whichever arm happens to be written
/// first — and the refusal an operator reads would then be an artefact of source
/// order rather than a fact about their sender. There is no build in which that
/// is worth discovering at runtime.
const _: () = assert!(
    MIN_FENCED_PROTOCOL_VERSION <= MAX_SUPPORTED_PROTOCOL_VERSION,
    "the fencing floor may not exceed the ceiling: no protocol version would be acceptable"
);

/// Why the ingress fence refused a worker frame.
///
/// Each variant is one adversary, named. They are deliberately NOT collapsed into
/// a single `Refused(String)`: the caller counts them separately, and a test that
/// asserts "the frame was refused" without asserting WHICH refusal fired would
/// pass against a fence that refuses everything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameRefusal {
    /// The sender does not speak the fencing contract, so its claims are absent
    /// rather than wrong.
    ///
    /// Refused rather than trusted. The alternative — treating an absent fence as
    /// "no objection" — would leave a downgrade path that readmits both
    /// adversaries this module refuses for any peer that simply omits the field.
    UnfencedSender {
        /// The version the sender claimed. `0` for a sender that carries no fence.
        claimed_version: u16,
    },
    /// The sender claims a protocol version ABOVE the highest this
    /// build implements.
    ///
    /// The mirror of [`Self::UnfencedSender`], and deliberately NOT folded into
    /// it, because the two name OPPOSITE recourse. An unfenced sender is older
    /// than this main and the fix is to upgrade the SENDER; a too-new sender is
    /// newer and the fix is to upgrade the MAIN. A single "bad protocol version"
    /// refusal would send half the operators who read it in the wrong direction,
    /// and the half that acted on it would make the outage worse.
    ///
    /// Refused rather than interpreted, for the reason the ceiling's own doc
    /// gives: the frame DECODES, so the alternative is to compare a generation
    /// and a worker id whose meaning was fixed after this binary was built, and
    /// then transition a ledger on the answer. A fence is worth exactly what its
    /// inputs mean.
    ProtocolTooNew {
        /// The version the sender claimed.
        claimed: u16,
        /// The highest version this build implements —
        /// [`MAX_SUPPORTED_PROTOCOL_VERSION`]. Carried on the refusal rather
        /// than left for the reader to look up, because an operator holding
        /// both numbers can tell which side to move and an operator holding one
        /// cannot.
        supported: u16,
    },
    /// The frame reports on an attempt that is durably placed on a DIFFERENT
    /// worker.
    ///
    /// Nobody necessarily lied: this is what a routing fault or a recovery race
    /// looks like from the main.
    WrongWorker {
        /// The worker the frame claims to be.
        claimed: String,
        /// The worker `attempts.worker_id` records.
        placed_on: String,
    },
    /// The frame's claimed sender is not the worker whose CONNECTION delivered it.
    ///
    /// Distinct from [`Self::WrongWorker`]: this one is a lie, catchable only
    /// because the transport independently identifies its peer.
    ImpersonatedSender {
        /// The worker the frame claims to be.
        claimed: String,
        /// The worker whose transport actually delivered it.
        connection: String,
    },
    /// The frame reports under a generation the attempt has already advanced past.
    ///
    /// The case the inbox seam cannot distinguish: without the epoch on the wire
    /// this frame would be keyed to the CURRENT generation and folded as if it
    /// belonged to it.
    StaleGeneration {
        /// The generation the frame claims.
        claimed: i64,
        /// The generation `attempts.lease_epoch` records.
        durable: i64,
    },
    /// The frame reports under a generation AHEAD of the durable one.
    ///
    /// Not a stale frame and not a benign one: the main allocates every epoch, so
    /// a claim above the durable value describes a generation the main never
    /// issued. Refused as a distinct variant so it cannot be read as ordinary
    /// staleness in a log.
    UnissuedGeneration {
        /// The generation the frame claims.
        claimed: i64,
        /// The generation `attempts.lease_epoch` records.
        durable: i64,
    },
}

impl FrameRefusal {
    /// A stable, lowercase label for metrics and the security-audit stream.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnfencedSender { .. } => "unfenced_sender",
            Self::ProtocolTooNew { .. } => "protocol_too_new",
            Self::WrongWorker { .. } => "wrong_worker",
            Self::ImpersonatedSender { .. } => "impersonated_sender",
            Self::StaleGeneration { .. } => "stale_generation",
            Self::UnissuedGeneration { .. } => "unissued_generation",
        }
    }
}

impl fmt::Display for FrameRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnfencedSender { claimed_version } => write!(
                f,
                "the sender speaks fencing protocol version {claimed_version}, below the minimum \
                 {MIN_FENCED_PROTOCOL_VERSION}; its frame carries no sender or generation to \
                 check, and accepting it would reinstate the wrong-worker and stale-generation \
                 paths for any peer that simply omits the field. Upgrade the SENDER to a build \
                 that speaks {MIN_FENCED_PROTOCOL_VERSION} or above; upgrading the main moves \
                 this refusal further out of reach, not closer"
            ),
            Self::ProtocolTooNew { claimed, supported } => write!(
                f,
                "the sender speaks fencing protocol version {claimed}, above the {supported} \
                 this build implements; its frame decodes but its coordinates were defined \
                 after this binary was built, so comparing them against the durable row would \
                 be a guess this fence declines to make. Upgrade the MAIN to a build that \
                 speaks {claimed}, or roll the SENDER back to {supported}. This is the \
                 OPPOSITE recourse from an unfenced sender, which needs the sender upgraded — \
                 the two are separate refusals so an operator is never told to move the wrong \
                 side"
            ),
            Self::WrongWorker { claimed, placed_on } => write!(
                f,
                "the frame reports as worker {claimed} on an attempt durably placed on \
                 {placed_on}; a worker may only report on attempts placed on it"
            ),
            Self::ImpersonatedSender {
                claimed,
                connection,
            } => write!(
                f,
                "the frame claims to come from worker {claimed} but arrived on worker \
                 {connection}'s transport; the connection identifies the sender and the frame \
                 does not get to disagree with it"
            ),
            Self::StaleGeneration { claimed, durable } => write!(
                f,
                "the frame reports under generation {claimed}, which the attempt has already \
                 advanced past (now {durable}); a superseded generation's report cannot \
                 transition the generation that replaced it"
            ),
            Self::UnissuedGeneration { claimed, durable } => write!(
                f,
                "the frame reports under generation {claimed}, ahead of the durable {durable}; \
                 the main allocates every generation, so this names one it never issued"
            ),
        }
    }
}

/// THE INGRESS FENCE. Decide whether a worker frame may reach the inbox seam.
///
/// # Order of checks, and why it is this order
///
/// 1. **Contract first, in BOTH directions.** A sender that speaks no version
///    has zeroed claims, and comparing a zeroed epoch against a durable `0`
///    would ACCEPT every first-generation frame from an unfenced peer. A sender
///    that speaks a version ABOVE
///    [`MAX_SUPPORTED_PROTOCOL_VERSION`] has claims this build has no definition
///    for, and comparing those would be a guess dressed as a check. The version
///    window is what makes the other comparisons meaningful rather than
///    accidental, and it is closed at both ends for one reason stated twice.
///
///    The two version arms are mutually exclusive — the window is non-empty by
///    the `const` assertion beside those constants — so their relative order is
///    NOT load-bearing and no rationale is invented for it. The floor is written
///    first because `0` is what `#[serde(default)]` produces and is therefore
///    the arm a real fleet reaches.
/// 2. **Impersonation before placement.** If the frame lies about who it is, the
///    placement comparison is being run against a value the sender chose. Catching
///    the lie first means the placement check only ever runs on a sender the
///    transport has already confirmed.
/// 3. **Placement before generation.** A wrong-worker frame's epoch is
///    meaningless — it belongs to a different worker's view of a different
///    dispatch — so reporting it as a stale generation would name the wrong
///    defect in the audit stream.
/// 4. **Generation always.** The epoch comparison is the one check with no
///    exemption. The placement check is skipped for an attempt that holds none
///    (see the comment at that branch for the wedge it would otherwise cause);
///    the epoch check is not, so "unplaced" is never a state a stale frame can
///    use as a bypass.
///
/// # Parameters
///
/// `connection_worker_id` is the identity the TRANSPORT attributes to the peer,
/// not anything the frame said. On the in-process and local-socket transports that
/// is the worker whose reactor is reading; it is the only sender fact that does
/// not come from the sender.
///
/// # Errors
///
/// Returns the first [`FrameRefusal`] that applies. A refusal is an expected
/// bounded event, not a fault: the caller drops the frame and keeps reading.
pub fn fence_inbound_attempt_frame(
    claimed: ClaimedFence<'_>,
    connection_worker_id: &str,
    durable: DurablePlacement<'_>,
) -> Result<(), FrameRefusal> {
    if claimed.protocol_version < MIN_FENCED_PROTOCOL_VERSION {
        return Err(FrameRefusal::UnfencedSender {
            claimed_version: claimed.protocol_version,
        });
    }
    if claimed.protocol_version > MAX_SUPPORTED_PROTOCOL_VERSION {
        return Err(FrameRefusal::ProtocolTooNew {
            claimed: claimed.protocol_version,
            supported: MAX_SUPPORTED_PROTOCOL_VERSION,
        });
    }
    if claimed.worker_id != connection_worker_id {
        return Err(FrameRefusal::ImpersonatedSender {
            claimed: claimed.worker_id.to_string(),
            connection: connection_worker_id.to_string(),
        });
    }
    // AN ATTEMPT WITH NO PLACEMENT SKIPS THE WORKER CHECK, DELIBERATELY.
    //
    // `attempts.worker_id` is NULL before the first dispatch and while parked, and
    // also for a narrow race: a terminal frame folding between the dispatch commit
    // and the placement writer's status read leaves the attempt claimed at
    // `pending` with no placement. That frame is a GENUINE terminal from the worker
    // actually running the stage.
    //
    // Refusing it here would convert the forgery into a redelivery wedge, because
    // a worker sends its terminal ONCE, so a refusal drops the outcome rather than
    // deferring it. Closing that residual needs the reactor to record
    // the placement BEFORE folding, which is a live-worker-path change, not
    // this fence's.
    //
    // The epoch check below still runs, and that is the point: an unplaced attempt
    // is exempt from the WORKER comparison only. A stale frame for one is still
    // stale, and refusing it wedges nothing, because the generation that superseded
    // it will produce its own terminal.
    if let Some(placed_on) = durable.worker_id
        && claimed.worker_id != placed_on
    {
        return Err(FrameRefusal::WrongWorker {
            claimed: claimed.worker_id.to_string(),
            placed_on: placed_on.to_string(),
        });
    }
    match claimed.lease_epoch.cmp(&durable.lease_epoch) {
        std::cmp::Ordering::Less => Err(FrameRefusal::StaleGeneration {
            claimed: claimed.lease_epoch,
            durable: durable.lease_epoch,
        }),
        std::cmp::Ordering::Greater => Err(FrameRefusal::UnissuedGeneration {
            claimed: claimed.lease_epoch,
            durable: durable.lease_epoch,
        }),
        std::cmp::Ordering::Equal => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKER: &str = "w-1";

    fn claim(epoch: i64, worker: &str) -> ClaimedFence<'_> {
        claim_at_version(MIN_FENCED_PROTOCOL_VERSION, epoch, worker)
    }

    /// A claim differing from [`claim`] in the VERSION alone.
    ///
    /// Every version case below drives this against `placed(3, WORKER)`, which
    /// is byte-for-byte the coordinates
    /// `the_matching_frame_from_the_placed_worker_at_the_live_generation_passes`
    /// accepts. So a refusal from one of them is the version arm firing and
    /// cannot be some other check catching a coordinate that was also wrong.
    fn claim_at_version(version: u16, epoch: i64, worker: &str) -> ClaimedFence<'_> {
        ClaimedFence {
            protocol_version: version,
            lease_epoch: epoch,
            worker_id: worker,
        }
    }

    fn placed(epoch: i64, worker: &str) -> DurablePlacement<'_> {
        DurablePlacement {
            lease_epoch: epoch,
            worker_id: Some(worker),
        }
    }

    /// THE NON-VACUITY CONTROL for every refusal below.
    ///
    /// Every adversarial case in this module differs from THIS call by exactly one
    /// coordinate. Without it a fence hardcoded to `Err` would satisfy all of them.
    #[test]
    fn the_matching_frame_from_the_placed_worker_at_the_live_generation_passes() {
        assert_eq!(
            fence_inbound_attempt_frame(claim(3, WORKER), WORKER, placed(3, WORKER)),
            Ok(())
        );
    }

    #[test]
    fn a_frame_from_a_worker_the_attempt_is_not_placed_on_is_refused() {
        // The sender is honest — it IS w-2, on w-2's connection — but the attempt
        // belongs to w-1. Nobody lied and the frame still may not transition.
        let refusal =
            fence_inbound_attempt_frame(claim(3, "w-2"), "w-2", placed(3, WORKER)).unwrap_err();
        assert_eq!(
            refusal,
            FrameRefusal::WrongWorker {
                claimed: "w-2".to_string(),
                placed_on: WORKER.to_string(),
            }
        );
    }

    #[test]
    fn a_frame_claiming_a_worker_other_than_its_connection_is_refused_as_impersonation() {
        // w-2's connection, claiming to be w-1 — the worker the attempt IS placed
        // on. Placement alone would have accepted it; only the connection identity
        // catches this, which is why both checks exist.
        let refusal =
            fence_inbound_attempt_frame(claim(3, WORKER), "w-2", placed(3, WORKER)).unwrap_err();
        assert_eq!(
            refusal,
            FrameRefusal::ImpersonatedSender {
                claimed: WORKER.to_string(),
                connection: "w-2".to_string(),
            }
        );
    }

    #[test]
    fn a_frame_from_a_superseded_generation_is_refused() {
        let refusal =
            fence_inbound_attempt_frame(claim(2, WORKER), WORKER, placed(3, WORKER)).unwrap_err();
        assert_eq!(
            refusal,
            FrameRefusal::StaleGeneration {
                claimed: 2,
                durable: 3,
            }
        );
    }

    #[test]
    fn a_frame_from_a_generation_the_main_never_issued_is_refused_distinctly() {
        let refusal =
            fence_inbound_attempt_frame(claim(9, WORKER), WORKER, placed(3, WORKER)).unwrap_err();
        assert_eq!(
            refusal,
            FrameRefusal::UnissuedGeneration {
                claimed: 9,
                durable: 3,
            },
            "an epoch ABOVE the durable one is not staleness and must not be logged as it"
        );
    }

    /// The downgrade path, refused.
    ///
    /// Generation `0` is the LEGITIMATE first generation of every attempt, so an
    /// unfenced sender's zeroed epoch matches a real durable `0` by value. If the
    /// contract check did not run first, this frame would be accepted — which is
    /// why the epoch is not overloaded to carry "did the sender speak".
    #[test]
    fn an_unfenced_sender_is_refused_even_when_its_zeroed_epoch_matches_the_durable_one() {
        let unfenced = ClaimedFence {
            protocol_version: 0,
            lease_epoch: 0,
            worker_id: WORKER,
        };
        let refusal = fence_inbound_attempt_frame(unfenced, WORKER, placed(0, WORKER)).unwrap_err();
        assert_eq!(refusal, FrameRefusal::UnfencedSender { claimed_version: 0 });

        // NON-VACUITY: the very same coordinates, from a sender that speaks the
        // contract, PASS. So the refusal above is the version check firing and not
        // generation 0 being rejected outright.
        assert_eq!(
            fence_inbound_attempt_frame(claim(0, WORKER), WORKER, placed(0, WORKER)),
            Ok(()),
            "generation 0 is a real generation; only the unfenced CLAIM is refused"
        );
    }

    /// THE FLOOR BOUNDARY, both sides of it.
    ///
    /// Asserted in terms of the constant rather than the literal `1`, so the
    /// case keeps testing the boundary after a bump instead of testing whatever
    /// `1` has come to mean.
    #[test]
    fn the_floor_admits_exactly_the_minimum_and_refuses_the_version_one_below_it() {
        assert_eq!(
            fence_inbound_attempt_frame(
                claim_at_version(MIN_FENCED_PROTOCOL_VERSION, 3, WORKER),
                WORKER,
                placed(3, WORKER)
            ),
            Ok(()),
            "EXACTLY the minimum is INSIDE the window; writing the floor comparison as \
             `<=` would refuse the lowest version this build honours and fence the fleet out"
        );

        let below = MIN_FENCED_PROTOCOL_VERSION.checked_sub(1).expect(
            "with a floor of 0 no claim can be below it and the UnfencedSender arm is \
             unreachable; that must be a loud failure here, never a silently skipped case",
        );
        assert_eq!(
            fence_inbound_attempt_frame(
                claim_at_version(below, 3, WORKER),
                WORKER,
                placed(3, WORKER)
            )
            .unwrap_err(),
            FrameRefusal::UnfencedSender {
                claimed_version: below
            },
            "one below the floor is refused, and BY NAME — a test asserting only that \
             SOME refusal fired would pass against a fence that refuses everything"
        );
    }

    /// THE CEILING BOUNDARY, both sides of it.
    ///
    /// The second assertion is the one a floor-only check fails: it would admit
    /// every value above the single version this build implements and then
    /// compare its epoch and worker id as though their meaning were known.
    #[test]
    fn the_ceiling_admits_exactly_the_supported_version_and_refuses_the_one_above_it() {
        assert_eq!(
            fence_inbound_attempt_frame(
                claim_at_version(MAX_SUPPORTED_PROTOCOL_VERSION, 3, WORKER),
                WORKER,
                placed(3, WORKER)
            ),
            Ok(()),
            "EXACTLY the ceiling is INSIDE the window; writing the ceiling comparison as \
             `>=` would refuse the only version this build actually speaks, which is the \
             off-by-one that costs a fleet rather than an adversary"
        );

        let above = MAX_SUPPORTED_PROTOCOL_VERSION.checked_add(1).expect(
            "with a ceiling of u16::MAX no claim can be too new and the ProtocolTooNew arm \
             is unreachable; that must be a loud failure here, never a silently skipped case",
        );
        assert_eq!(
            fence_inbound_attempt_frame(
                claim_at_version(above, 3, WORKER),
                WORKER,
                placed(3, WORKER)
            )
            .unwrap_err(),
            FrameRefusal::ProtocolTooNew {
                claimed: above,
                supported: MAX_SUPPORTED_PROTOCOL_VERSION,
            },
            "one above the ceiling is refused, and BY NAME as too new"
        );
    }

    /// Distance above the ceiling changes nothing — including the three values
    /// a floor-only fence would ACCEPT.
    ///
    /// The literals are named rather than derived because the point is that
    /// a floor-only fence passes these SPECIFIC wire values. `u16::MAX` is here for its own
    /// reason: it is the value a hostile peer reaches for, and a ceiling written
    /// with wrapping arithmetic would fold it back inside the window.
    #[test]
    fn no_claim_above_the_ceiling_is_admitted_however_far_above_it_lands() {
        let hostile: Vec<u16> = [2u16, 99, u16::MAX]
            .into_iter()
            .filter(|version| *version > MAX_SUPPORTED_PROTOCOL_VERSION)
            .collect();
        assert!(
            !hostile.is_empty(),
            "every surveyed value now sits INSIDE the window, so this case asserts \
             nothing; add a value above MAX_SUPPORTED_PROTOCOL_VERSION rather than \
             leaving a test that passes by observing an empty loop"
        );
        for version in hostile {
            assert_eq!(
                fence_inbound_attempt_frame(
                    claim_at_version(version, 3, WORKER),
                    WORKER,
                    placed(3, WORKER)
                )
                .unwrap_err(),
                FrameRefusal::ProtocolTooNew {
                    claimed: version,
                    supported: MAX_SUPPORTED_PROTOCOL_VERSION,
                },
                "protocol version {version} reached the placement and generation checks \
                 on the shipped fence; it must now be refused as too new"
            );
        }
    }

    /// THE TWO VERSION REFUSALS MUST NOT MERGE, because they name OPPOSITE
    /// recourse.
    ///
    /// Two refusals with opposite recourse merged into one is the defect, held at
    /// the boundary where it would do the most damage. One "bad protocol version" refusal would be
    /// cheaper and would tell an operator whose sender is too OLD to upgrade
    /// their main, and an operator whose sender is too NEW to upgrade their
    /// sender — each of them the wrong side, each of them a second outage.
    ///
    /// It also guards the floor against regression: version `0` must still answer
    /// `UnfencedSender`. A ceiling written
    /// with wrapping or signed arithmetic is the plausible way to break it.
    #[test]
    fn the_two_version_refusals_stay_distinguishable_and_name_opposite_sides_to_move() {
        let too_old =
            fence_inbound_attempt_frame(claim_at_version(0, 0, WORKER), WORKER, placed(0, WORKER))
                .unwrap_err();
        let too_new = fence_inbound_attempt_frame(
            claim_at_version(u16::MAX, 3, WORKER),
            WORKER,
            placed(3, WORKER),
        )
        .unwrap_err();

        assert_eq!(
            too_old,
            FrameRefusal::UnfencedSender { claimed_version: 0 },
            "version 0 is the unfenced sender and stays it; the ceiling must not \
             capture the bottom of the range"
        );
        assert_eq!(
            too_new,
            FrameRefusal::ProtocolTooNew {
                claimed: u16::MAX,
                supported: MAX_SUPPORTED_PROTOCOL_VERSION,
            },
        );
        assert_ne!(
            too_old.as_str(),
            too_new.as_str(),
            "the audit labels are what an operator COUNTS; one label for both would \
             make the two populations indistinguishable in a dashboard"
        );

        // A refusal must name an action its reader can invoke.
        // Asserted on the directive itself, and on its ABSENCE in the sibling,
        // because "each message says something" is satisfiable by two messages
        // that say the same thing.
        let old_text = too_old.to_string();
        let new_text = too_new.to_string();
        assert!(
            old_text.contains("Upgrade the SENDER") && !old_text.contains("Upgrade the MAIN"),
            "a sender below the fencing floor carries no fencing facts, so the invocable \
             action is to upgrade the SENDER: {old_text}"
        );
        assert!(
            new_text.contains("Upgrade the MAIN") && !new_text.contains("Upgrade the SENDER"),
            "a too-new sender is ahead of this build, so the invocable action is to \
             upgrade the MAIN: {new_text}"
        );

        // Both NUMBERS in both messages. An operator holding only the version
        // that arrived cannot tell which side to move, so a message carrying one
        // number names an action nobody can act on.
        assert!(
            old_text.contains(&MIN_FENCED_PROTOCOL_VERSION.to_string()) && old_text.contains('0'),
            "the unfenced refusal must state both the claimed version and the floor: {old_text}"
        );
        assert!(
            new_text.contains(&u16::MAX.to_string())
                && new_text.contains(&MAX_SUPPORTED_PROTOCOL_VERSION.to_string()),
            "the too-new refusal must state both the claimed version and the ceiling: {new_text}"
        );
    }

    /// An attempt with NO placement is exempt from the worker check — and only
    /// from that one.
    ///
    /// The exemption is not a gap this fence forgot. A terminal frame can
    /// legitimately arrive while the attempt is momentarily unplaced, and a worker
    /// sends its terminal ONCE, so refusing would DROP the outcome — adding the
    /// check alone would convert the forgery into a redelivery wedge.
    ///
    /// The second half is what keeps the exemption narrow: the epoch comparison
    /// still applies, so an unplaced attempt is not a hole a stale frame can walk
    /// through. Both directions are asserted, because asserting only the pass
    /// would be indistinguishable from disabling the fence for unplaced attempts.
    #[test]
    fn an_unplaced_attempt_skips_only_the_worker_check() {
        let unplaced = DurablePlacement {
            lease_epoch: 3,
            worker_id: None,
        };
        assert_eq!(
            fence_inbound_attempt_frame(claim(3, WORKER), WORKER, unplaced),
            Ok(()),
            "a live-generation terminal for a momentarily unplaced attempt must NOT \
             be dropped; refusing it wedges an outcome the worker will not resend"
        );
        assert_eq!(
            fence_inbound_attempt_frame(claim(2, WORKER), WORKER, unplaced).unwrap_err(),
            FrameRefusal::StaleGeneration {
                claimed: 2,
                durable: 3,
            },
            "but a SUPERSEDED generation's frame is still refused, so the exemption \
             is the worker check alone and not the whole fence"
        );
    }

    /// THE TWO SPELLINGS OF ONE NUMBER, pinned equal.
    ///
    /// [`MIN_FENCED_PROTOCOL_VERSION`] is declared here because `kata-core` sits
    /// BELOW `kata-transport` and cannot import the wire constant into a `const`.
    /// Two independent declarations of one contract version is exactly the
    /// two-readers-diverge shape: bump
    /// [`kata_transport::ATTEMPT_PROTOCOL_VERSION`] alone and every worker would
    /// announce a version this fence silently treats as unfenced, refusing every
    /// frame in the fleet. This test is the mechanism that makes the drift
    /// impossible to ship rather than merely unlikely.
    #[test]
    fn the_core_and_transport_protocol_versions_are_one_number() {
        assert_eq!(
            MIN_FENCED_PROTOCOL_VERSION,
            kata_transport::ATTEMPT_PROTOCOL_VERSION,
            "the fence's minimum and the wire's announced version are ONE contract \
             version spelled in two crates; bumping either alone fences the whole \
             fleet out"
        );
    }

    /// THE CEILING IS THE VERSION THIS BUILD ANNOUNCES.
    ///
    /// A sibling of the pin above and not a duplicate of it: that one holds the
    /// FLOOR against the wire constant, this one holds the CEILING. The two
    /// spellings are separate facts (see the constants' docs) that are equal
    /// today, and each needs its own tie to the wire or the untied one drifts.
    ///
    /// The ceiling's tie is the sharper of the two, because the version a build
    /// puts on its OWN frames is by definition the newest it implements.
    /// Bump [`kata_transport::ATTEMPT_PROTOCOL_VERSION`] alone and this main
    /// refuses, as `ProtocolTooNew`, every frame its own workers emit — the
    /// fleet-wide outage in its most confusing form, since the refusal would
    /// tell the operator to upgrade the main they just upgraded.
    #[test]
    fn the_supported_ceiling_is_the_version_the_wire_announces() {
        assert_eq!(
            MAX_SUPPORTED_PROTOCOL_VERSION,
            kata_transport::ATTEMPT_PROTOCOL_VERSION,
            "the fence's ceiling and the version workers announce are ONE number \
             spelled in two crates; a build cannot implement less than it advertises"
        );
    }

    /// THE TWO FENCES MAY NOT SHARE A LABEL.
    ///
    /// The worker side grew its own refusal vocabulary
    /// ([`kata_transport::ControlRefusal`]) so the attempt fence stopped being
    /// one-sided. The two run on OPPOSITE ends of one protocol and their
    /// refusals mean opposite things: `stale_generation` here is *"the worker is
    /// behind"*, and the same word on the worker would be *"the main is
    /// behind"*. One shared label puts two populations in one metric dimension
    /// and an operator counting it cannot tell which end of the fleet to move —
    /// which is exactly what `the_provider_refusal_labels_cannot_be_confused_
    /// with_the_attempt_fences` already refuses for the provider protocol.
    ///
    /// It lives HERE rather than beside `ControlRefusal` because `kata-core`
    /// depends on `kata-transport` and not the other way round, so this is the
    /// only crate that can name both vocabularies without a dependency cycle.
    #[test]
    fn the_two_fences_share_no_label() {
        use kata_transport::ControlRefusal;

        let main_side = [
            FrameRefusal::UnfencedSender { claimed_version: 0 }.as_str(),
            FrameRefusal::ProtocolTooNew {
                claimed: 0,
                supported: 0,
            }
            .as_str(),
            FrameRefusal::WrongWorker {
                claimed: String::new(),
                placed_on: String::new(),
            }
            .as_str(),
            FrameRefusal::ImpersonatedSender {
                claimed: String::new(),
                connection: String::new(),
            }
            .as_str(),
            FrameRefusal::StaleGeneration {
                claimed: 0,
                durable: 0,
            }
            .as_str(),
            FrameRefusal::UnissuedGeneration {
                claimed: 0,
                durable: 0,
            }
            .as_str(),
        ];
        let zero = ulid::Ulid::nil();
        let worker_side = [
            ControlRefusal::UnfencedCommander { claimed_version: 0 }.as_str(),
            ControlRefusal::ProtocolTooNew {
                claimed: 0,
                supported: 0,
            }
            .as_str(),
            ControlRefusal::WrongAttempt {
                commanded: zero,
                holding: zero,
            }
            .as_str(),
            ControlRefusal::MisaddressedWorker {
                commanded: String::new(),
                holding: String::new(),
            }
            .as_str(),
            ControlRefusal::StaleCommandGeneration {
                commanded: 0,
                holding: 0,
            }
            .as_str(),
            ControlRefusal::UnheldCommandGeneration {
                commanded: 0,
                holding: 0,
            }
            .as_str(),
        ];
        assert_eq!(
            main_side.len(),
            worker_side.len(),
            "the fence is two-sided; a side that grows a refusal the other cannot express \
             is the asymmetry this pair exists to hold closed"
        );
        for worker_label in worker_side {
            assert!(
                !main_side.contains(&worker_label),
                "{worker_label} is used by BOTH fences; the two refusal vocabularies must \
                 stay separable in a metric"
            );
        }
    }

    /// THE TWO FENCES ENFORCE ONE VERSION WINDOW.
    ///
    /// A build that refuses an inbound FRAME at a version it obeys a COMMAND at
    /// is honouring half its own protocol, and the half it honours would be the
    /// half an adversary picks. Three spellings of one number — this module's
    /// pair, `kata_transport::ControlRefusal`'s pair, and the wire constant —
    /// each need a tie or the untied one drifts.
    #[test]
    fn the_two_fences_enforce_one_window() {
        assert_eq!(
            MIN_FENCED_PROTOCOL_VERSION,
            kata_transport::MIN_FENCED_COMMAND_VERSION,
            "the inbound-frame floor and the inbound-command floor are ONE contract version"
        );
        assert_eq!(
            MAX_SUPPORTED_PROTOCOL_VERSION,
            kata_transport::MAX_SUPPORTED_COMMAND_VERSION,
            "the inbound-frame ceiling and the inbound-command ceiling are ONE contract version"
        );
    }

    /// The audit labels must be distinct, because they are what a operator counts.
    #[test]
    fn every_refusal_has_its_own_label() {
        let labels = [
            FrameRefusal::UnfencedSender { claimed_version: 0 }.as_str(),
            FrameRefusal::ProtocolTooNew {
                claimed: 0,
                supported: 0,
            }
            .as_str(),
            FrameRefusal::WrongWorker {
                claimed: String::new(),
                placed_on: String::new(),
            }
            .as_str(),
            FrameRefusal::ImpersonatedSender {
                claimed: String::new(),
                connection: String::new(),
            }
            .as_str(),
            FrameRefusal::StaleGeneration {
                claimed: 0,
                durable: 0,
            }
            .as_str(),
            FrameRefusal::UnissuedGeneration {
                claimed: 0,
                durable: 0,
            }
            .as_str(),
        ];
        let mut unique = labels.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            labels.len(),
            "refusal labels must be distinct"
        );
    }
}
