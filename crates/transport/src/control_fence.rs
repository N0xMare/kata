//! The WORKER-side half of the attempt fence.
//!
//! # The asymmetry this closes
//!
//! The attempt fence shipped on ONE side of a two-sided protocol. The main
//! refuses a malformed or misdirected worker frame through
//! `kata_core::operational::ingress_fence::FrameRefusal` — six named adversaries,
//! a counted label per adversary, compared against the durable `attempts` row.
//! The worker's inbound check was one boolean:
//!
//! ```ignore
//! let for_this_attempt = target == assignment_id
//!     && fence_seen.lease_epoch == fence.lease_epoch;
//! ```
//!
//! Two coordinates, no vocabulary, and a `debug!` line for everything it dropped.
//! That is not merely less expressive than the main's fence — it ADMITS frames
//! the main's own reasoning says must be refused, and the version window is the
//! sharp case. `AttemptFence::protocol_version` was never read here, so a
//! `WorkerControl::Stop` claiming version `0` (a commander that predates fencing,
//! or a `#[serde(default)]` frame that carries no fencing facts at all) or
//! version `99` (a commander this build has no definition for) was OBEYED, as
//! long as its epoch matched — and obeying it means killing a running stage.
//! `fence_seen.worker_id` was not read either, so a stop addressed to a different
//! worker was obeyed by whichever worker received it.
//!
//! # Symmetry, and the one main-side refusal that is NOT representable here
//!
//! Five of the main's six refusals have an exact worker-side mirror. The sixth,
//! `FrameRefusal::ImpersonatedSender`, does NOT, and it is named as absent rather
//! than approximated: that refusal is only catchable because the main holds an
//! identity for the peer that the peer did not supply — the connection the frame
//! arrived on. A worker has ONE link, to its main, and no second name for the
//! thing at the other end of it. A worker-side "impersonation" check could only
//! compare the frame against itself. This module therefore claims five mirrors
//! and one refusal the main has no need for, [`ControlRefusal::WrongAttempt`] —
//! the main resolves an inbound frame's attempt BY id and cannot be handed the
//! wrong one, while a worker is handed whatever the link delivers.
//!
//! Certifying the commander is the same unimplemented binding the main side
//! lacks for certifying the worker, and closing it here would not be a fence
//! change.
//!
//! # Why a refused control frame is not an error, and not a stop either
//!
//! Same reason the main's is: a refusal is expected and bounded. Recovery
//! legitimately produces control frames for superseded generations. Killing the
//! link over one would turn a fenced frame into an outage, and OBEYING one is a
//! cross-generation kill of whatever the worker happens to be running. The caller
//! drops the frame, counts the refusal, and keeps executing.
//!
//! # Why the labels do not rhyme with the main's
//!
//! `stale_generation` means "the SENDER is behind" on the main and would mean
//! "the COMMANDER is behind" here — one word, two directions, one metric
//! dimension an operator cannot separate. `ProviderRefusal` already solved this
//! by prefixing its labels; these are prefixed for the same reason.
//!
//! `the_two_fences_share_no_label` and `the_two_fences_enforce_one_window` hold
//! both properties, and they live in `kata-core`'s `ingress_fence` module rather
//! than beside this one because `kata-core` DEPENDS on `kata-transport` — so
//! core is the only crate that can see both vocabularies, and a dev-dependency
//! back the other way would be a cycle.

use std::fmt;

use ulid::Ulid;

use crate::types::{ATTEMPT_PROTOCOL_VERSION, AttemptFence, WorkerControl};

/// The lowest fencing protocol version a worker will act on a command from.
///
/// The same number as the main's floor and as [`ATTEMPT_PROTOCOL_VERSION`], for
/// the same reason: a build that stops honouring the version it announces fences
/// its own fleet out. Spelled as its own constant rather than used inline so the
/// window has two named ends — see [`MAX_SUPPORTED_COMMAND_VERSION`].
pub const MIN_FENCED_COMMAND_VERSION: u16 = ATTEMPT_PROTOCOL_VERSION;

/// The highest fencing protocol version this build can INTERPRET a command at.
///
/// A different question from the floor, exactly as on the main side: the floor
/// asks *"does this commander carry fencing facts at all?"*, the ceiling asks
/// *"do I know what its facts MEAN?"*. Every fence field is `#[serde(default)]`,
/// so a command from a protocol this build never learned still decodes into a
/// `u16`, an `i64` and a string — what it does not do is arrive with the meaning
/// those fields had when the commander wrote them, and acting on it kills a
/// running stage on a guess.
pub const MAX_SUPPORTED_COMMAND_VERSION: u16 = ATTEMPT_PROTOCOL_VERSION;

/// The window may not be empty, as a COMPILE error rather than a test — the
/// sibling reasoning to `kata-core`'s identical assertion. With the floor above
/// the ceiling, every commander is simultaneously too old and too new and the
/// refusal an operator reads is an artefact of which arm was written first.
const _: () = assert!(
    MIN_FENCED_COMMAND_VERSION <= MAX_SUPPORTED_COMMAND_VERSION,
    "the command fencing floor may not exceed the ceiling: no version would be acceptable"
);

/// What an inbound [`WorkerControl`] frame CLAIMS about who it commands.
///
/// A borrowed view rather than the frame, so the decision is over the scalars it
/// turns on and a test can state an adversary without building a whole frame.
/// Build it from a real frame with [`Self::from_frame`].
#[derive(Clone, Copy, Debug)]
pub struct CommandedAttempt<'a> {
    /// The attempt the command names.
    pub assignment_id: Ulid,
    /// The fencing contract the COMMANDER speaks. `0` means it speaks none.
    pub protocol_version: u16,
    /// The generation the command is issued against.
    pub lease_epoch: i64,
    /// The worker the command is addressed to.
    pub worker_id: &'a str,
}

impl<'a> CommandedAttempt<'a> {
    /// Lift the fencing claims off a real control frame.
    #[must_use]
    pub fn from_frame(frame: &'a WorkerControl) -> Option<Self> {
        let (assignment_id, fence) = frame.fenced_attempt()?;
        Some(Self {
            assignment_id,
            protocol_version: fence.protocol_version,
            lease_epoch: fence.lease_epoch,
            worker_id: fence.worker_id.as_str(),
        })
    }
}

/// What the worker actually HOLDS — the attempt it is running right now.
///
/// The mirror of the main's `DurablePlacement`, and the mirror is exact in the
/// one way that matters: neither side compares a frame against another frame.
/// The main compares against its durable row; the worker compares against the
/// assignment it was handed and is executing. Build it with [`Self::holding`].
#[derive(Clone, Copy, Debug)]
pub struct HeldAttempt<'a> {
    /// The attempt this worker is running.
    pub assignment_id: Ulid,
    /// The generation it was dispatched under, from
    /// [`crate::types::CapsuleAssignment::lease_epoch`].
    pub lease_epoch: i64,
    /// This worker's own name, from
    /// [`crate::types::CapsuleAssignment::placed_on`]. EMPTY means the frame
    /// was never stamped — see the exemption in
    /// [`fence_inbound_control_frame`].
    pub worker_id: &'a str,
}

impl<'a> HeldAttempt<'a> {
    /// The attempt a worker holds, derived from the assignment and the fence it
    /// already echoes for it.
    ///
    /// Takes the echoed [`AttemptFence`] rather than re-reading the assignment's
    /// fields, so the coordinates the worker DEFENDS and the coordinates it
    /// REPORTS are provably one value. Two derivations here is how a worker
    /// comes to refuse commands for the generation it is telling the main it is
    /// running.
    #[must_use]
    pub fn holding(assignment_id: Ulid, echoed: &'a AttemptFence) -> Self {
        Self {
            assignment_id,
            lease_epoch: echoed.lease_epoch,
            worker_id: echoed.worker_id.as_str(),
        }
    }
}

/// Why a worker refused a control frame.
///
/// One variant per adversary, named, for the reason the main's sibling gives: a
/// test that asserts "the frame was refused" without asserting WHICH refusal
/// fired passes against a fence that refuses everything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRefusal {
    /// The commander does not speak the fencing contract, so its claims are
    /// absent rather than wrong.
    ///
    /// The mirror of `FrameRefusal::UnfencedSender` and refused for the mirrored
    /// reason: treating an absent fence as "no objection" would leave a
    /// downgrade path in which any peer that
    /// omits the field can stop any stage this worker is running.
    UnfencedCommander {
        /// The version the commander claimed. `0` for a frame with no fence.
        claimed_version: u16,
    },
    /// The commander claims a version ABOVE the highest this build implements.
    ///
    /// Kept separate from [`Self::UnfencedCommander`] because the two name
    /// OPPOSITE recourse — upgrade the WORKER here, upgrade the MAIN there — and
    /// one merged "bad version" refusal sends half the operators who read it to
    /// the wrong side of the connection.
    ProtocolTooNew {
        /// The version the commander claimed.
        claimed: u16,
        /// The highest this build implements — [`MAX_SUPPORTED_COMMAND_VERSION`].
        /// Carried on the refusal so an operator holding both numbers can tell
        /// which side to move.
        supported: u16,
    },
    /// The command names an attempt this worker is not running.
    ///
    /// The one refusal with NO main-side counterpart, and deliberately so: the
    /// main resolves an inbound frame's attempt by id, so it can never be handed
    /// "the wrong attempt" — a worker is handed whatever arrives on the link.
    /// Not necessarily an adversary: a queued stop for an attempt this worker
    /// already finished looks exactly like this.
    WrongAttempt {
        /// The attempt the command names.
        commanded: Ulid,
        /// The attempt this worker is running.
        holding: Ulid,
    },
    /// The command is addressed to a DIFFERENT worker.
    ///
    /// The mirror of `FrameRefusal::WrongWorker`. Nobody necessarily lied: this
    /// is what a routing fault looks like from the worker, and obeying it kills
    /// a stage on behalf of a command meant for someone else.
    MisaddressedWorker {
        /// The worker the command names.
        commanded: String,
        /// The worker that received it.
        holding: String,
    },
    /// The command was issued against a generation this worker has moved past.
    ///
    /// The mirror of `FrameRefusal::StaleGeneration`, and the recourse is
    /// MAIN-side: a stop built from a remembered epoch rather than re-read from
    /// the durable row is exactly how a stale command is minted.
    StaleCommandGeneration {
        /// The generation the command names.
        commanded: i64,
        /// The generation this worker holds.
        holding: i64,
    },
    /// The command was issued against a generation AHEAD of the one this worker
    /// holds.
    ///
    /// The mirror of `FrameRefusal::UnissuedGeneration` in position, NOT in
    /// meaning, and the difference is why it gets its own name. The main can say
    /// "I never issued that" because it allocates every epoch. A worker allocates
    /// none, so it can only say "I do not hold that one" — and the fact it
    /// actually reports is the more useful one: this worker's assignment has been
    /// SUPERSEDED, its own results are about to be refused by the main's ingress
    /// fence, and the command belongs to its successor.
    UnheldCommandGeneration {
        /// The generation the command names.
        commanded: i64,
        /// The generation this worker holds.
        holding: i64,
    },
}

impl ControlRefusal {
    /// A stable, lowercase label for metrics and logs.
    ///
    /// Prefixed away from the main-side `FrameRefusal` labels on purpose: the two
    /// fences run on opposite ends of one protocol and a shared word like
    /// `stale_generation` would put two different populations in one metric
    /// dimension. `the_two_fences_share_no_label` enforces it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnfencedCommander { .. } => "unfenced_commander",
            Self::ProtocolTooNew { .. } => "commander_protocol_too_new",
            Self::WrongAttempt { .. } => "wrong_attempt",
            Self::MisaddressedWorker { .. } => "misaddressed_worker",
            Self::StaleCommandGeneration { .. } => "stale_command_generation",
            Self::UnheldCommandGeneration { .. } => "unheld_command_generation",
        }
    }
}

impl fmt::Display for ControlRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnfencedCommander { claimed_version } => write!(
                f,
                "the commander speaks fencing protocol version {claimed_version}, below the \
                 minimum {MIN_FENCED_COMMAND_VERSION}; its command names no generation this \
                 worker can check, and obeying it would let any peer that omits the field stop \
                 a running stage. Upgrade the MAIN to a build that speaks \
                 {MIN_FENCED_COMMAND_VERSION} or above"
            ),
            Self::ProtocolTooNew { claimed, supported } => write!(
                f,
                "the commander speaks fencing protocol version {claimed}, above the {supported} \
                 this build implements; its command decodes but its coordinates were defined \
                 after this binary was built, so acting on them would kill a running stage on a \
                 guess. Upgrade the WORKER to a build that speaks {claimed}, or roll the MAIN \
                 back to {supported}. This is the OPPOSITE recourse from an unfenced commander, \
                 which needs the MAIN upgraded"
            ),
            Self::WrongAttempt { commanded, holding } => write!(
                f,
                "the command names attempt {commanded} but this worker is running {holding}; a \
                 command may only reach the attempt it names"
            ),
            Self::MisaddressedWorker { commanded, holding } => write!(
                f,
                "the command is addressed to worker {commanded} but arrived at {holding}; \
                 obeying it would stop this worker's stage on behalf of a command meant for \
                 another"
            ),
            Self::StaleCommandGeneration { commanded, holding } => write!(
                f,
                "the command was issued against generation {commanded}, which this worker has \
                 moved past (now running {holding}); a superseded generation's command cannot \
                 stop the generation that replaced it. Re-mint the command from the durable \
                 attempts row rather than from a remembered epoch"
            ),
            Self::UnheldCommandGeneration { commanded, holding } => write!(
                f,
                "the command was issued against generation {commanded}, ahead of the {holding} \
                 this worker holds; this worker's assignment has been superseded and the command \
                 belongs to its successor"
            ),
        }
    }
}

/// THE CONTROL FENCE. Decide whether a control frame may act on the attempt this
/// worker is running.
///
/// # Order of checks, and why it is this order
///
/// 1. **Contract first, at BOTH ends.** A commander that speaks no version has
///    zeroed claims, and `0` is the legitimate first generation of every attempt
///    — so comparing a zeroed epoch would OBEY every first-generation command
///    from an unfenced peer. A commander above the ceiling has claims this build
///    has no definition for. The window is what makes every comparison below it
///    mean something. The two arms are mutually exclusive (the `const` assertion
///    above), so their relative order is not load-bearing; the floor is written
///    first because `0` is what `#[serde(default)]` produces.
/// 2. **Attempt before worker.** A command for a DIFFERENT attempt is legitimately
///    addressed to a different worker — that attempt is placed elsewhere — so
///    checking the address first would report a misaddressed worker for a frame
///    whose only defect is that it is not this attempt's.
/// 3. **Worker before generation.** A misaddressed command's epoch belongs to
///    another worker's view of another dispatch, so reporting it as a generation
///    problem names the wrong defect in an operator's log.
/// 4. **Generation always.** The one check with no exemption. The ADDRESS check
///    is skipped for an assignment that carries no stamp (below); the generation
///    check is not, so "unstamped" is never a state a stale command can use as a
///    bypass.
///
/// # Errors
///
/// The first [`ControlRefusal`] that applies. A refusal is an expected bounded
/// event, not a fault: the caller drops the frame and keeps executing.
pub fn fence_inbound_control_frame(
    commanded: CommandedAttempt<'_>,
    held: HeldAttempt<'_>,
) -> Result<(), ControlRefusal> {
    if commanded.protocol_version < MIN_FENCED_COMMAND_VERSION {
        return Err(ControlRefusal::UnfencedCommander {
            claimed_version: commanded.protocol_version,
        });
    }
    if commanded.protocol_version > MAX_SUPPORTED_COMMAND_VERSION {
        return Err(ControlRefusal::ProtocolTooNew {
            claimed: commanded.protocol_version,
            supported: MAX_SUPPORTED_COMMAND_VERSION,
        });
    }
    if commanded.assignment_id != held.assignment_id {
        return Err(ControlRefusal::WrongAttempt {
            commanded: commanded.assignment_id,
            holding: held.assignment_id,
        });
    }
    // AN UNSTAMPED ASSIGNMENT SKIPS THE ADDRESS CHECK, DELIBERATELY.
    //
    // `types::CapsuleAssignment::placed_on` is EMPTY for a frame that never
    // reached `WorkerPoolSupervisor::dispatch_to` — the seam that stamps it —
    // and for a blob that carries no stamp. This is the mirror of the main
    // fence's `attempts.worker_id IS NULL` exemption and it exists for the
    // mirrored reason: refusing here would make a worker holding an unstamped
    // assignment UNSTOPPABLE, which converts a missing stamp into a stage that
    // no operator cancel can reach.
    //
    // The generation check below still runs, and that is what keeps the
    // exemption narrow: an unstamped assignment is exempt from the ADDRESS
    // comparison only.
    if !held.worker_id.is_empty() && commanded.worker_id != held.worker_id {
        return Err(ControlRefusal::MisaddressedWorker {
            commanded: commanded.worker_id.to_string(),
            holding: held.worker_id.to_string(),
        });
    }
    match commanded.lease_epoch.cmp(&held.lease_epoch) {
        std::cmp::Ordering::Less => Err(ControlRefusal::StaleCommandGeneration {
            commanded: commanded.lease_epoch,
            holding: held.lease_epoch,
        }),
        std::cmp::Ordering::Greater => Err(ControlRefusal::UnheldCommandGeneration {
            commanded: commanded.lease_epoch,
            holding: held.lease_epoch,
        }),
        std::cmp::Ordering::Equal => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use smol_str::SmolStr;

    use super::*;

    const WORKER: &str = "w-1";

    fn attempt() -> Ulid {
        Ulid::from_parts(1, 1)
    }

    fn other_attempt() -> Ulid {
        Ulid::from_parts(2, 2)
    }

    /// A held capsule frame, built HERE rather than through a fixture crate —
    /// `kata-transport` dev-depends on itself for `test-support`, so inside
    /// `cfg(test)` the crate's own `crate::types::CapsuleAssignment` and a
    /// fixture crate's copy are two distinct types and will not unify.
    fn capsule_at(epoch: i64, worker: &str) -> crate::types::CapsuleAssignment {
        crate::types::CapsuleAssignment {
            attempt_id: attempt(),
            execution_id: attempt(),
            occurrence_id: kata_types::execution_contract::OccurrenceId(
                kata_types::primitives::FixedBytes::new([3u8; 32]),
            ),
            capsule: crate::types::CapsuleRef {
                id: kata_types::execution_contract::CapsuleId(
                    kata_types::primitives::ContentHash::new([7u8; 32]),
                ),
                object: kata_types::primitives::ObjectId::new([9u8; 32]),
                size_bytes: 0,
            },
            lease_epoch: epoch,
            placed_on: SmolStr::new(worker),
            command_id: None,
            effect_domain: None,
            start_deadline_ms: None,
            progress_visibility: kata_types::workflow::ProgressVisibility::Off,
            trace: crate::types::TraceContext::default(),
        }
    }

    /// The fence a worker echoes for the attempt it holds — the generation and
    /// the placement, verbatim. Built HERE rather than through a frame fixture:
    /// the fence is the only fact this module's tests need.
    fn echoed_at(epoch: i64, worker: &str) -> AttemptFence {
        AttemptFence {
            protocol_version: crate::types::ATTEMPT_PROTOCOL_VERSION,
            lease_epoch: epoch,
            worker_id: SmolStr::new(worker),
        }
    }

    fn held(epoch: i64, worker: &str) -> HeldAttempt<'_> {
        HeldAttempt {
            assignment_id: attempt(),
            lease_epoch: epoch,
            worker_id: worker,
        }
    }

    fn command(epoch: i64, worker: &str) -> CommandedAttempt<'_> {
        command_at_version(MIN_FENCED_COMMAND_VERSION, epoch, worker)
    }

    /// A command differing from [`command`] in the VERSION alone. Every version
    /// case below drives this against `held(3, WORKER)`, byte-for-byte the
    /// coordinates the non-vacuity control accepts — so a refusal from one of
    /// them is the version arm firing and not some other coordinate.
    fn command_at_version(version: u16, epoch: i64, worker: &str) -> CommandedAttempt<'_> {
        CommandedAttempt {
            assignment_id: attempt(),
            protocol_version: version,
            lease_epoch: epoch,
            worker_id: worker,
        }
    }

    /// THE NON-VACUITY CONTROL. Every adversarial case differs from this call by
    /// exactly one coordinate; without it a fence hardcoded to `Err` satisfies
    /// all of them.
    #[test]
    fn the_command_for_the_held_attempt_at_the_held_generation_passes() {
        assert_eq!(
            fence_inbound_control_frame(command(3, WORKER), held(3, WORKER)),
            Ok(())
        );
    }

    /// THE HOLE. Version `0` — what `#[serde(default)]` produces for a command
    /// that carries no fencing facts — was OBEYED by the shipped worker loop,
    /// because it never read `protocol_version` at all.
    #[test]
    fn an_unfenced_commander_is_refused_even_when_its_zeroed_epoch_matches() {
        let unfenced = CommandedAttempt {
            assignment_id: attempt(),
            protocol_version: 0,
            lease_epoch: 0,
            worker_id: WORKER,
        };
        assert_eq!(
            fence_inbound_control_frame(unfenced, held(0, WORKER)).unwrap_err(),
            ControlRefusal::UnfencedCommander { claimed_version: 0 }
        );

        // NON-VACUITY: the very same coordinates from a commander that speaks
        // the contract PASS, so generation 0 is not being rejected outright.
        assert_eq!(
            fence_inbound_control_frame(command(0, WORKER), held(0, WORKER)),
            Ok(()),
            "generation 0 is a real generation; only the unfenced CLAIM is refused"
        );
    }

    /// THE OTHER HOLE, and the boundary on both sides of it.
    #[test]
    fn the_version_window_admits_exactly_its_ends_and_refuses_one_step_outside_each() {
        assert_eq!(
            fence_inbound_control_frame(
                command_at_version(MIN_FENCED_COMMAND_VERSION, 3, WORKER),
                held(3, WORKER)
            ),
            Ok(()),
            "EXACTLY the minimum is INSIDE the window; a `<=` floor fences the fleet out"
        );
        assert_eq!(
            fence_inbound_control_frame(
                command_at_version(MAX_SUPPORTED_COMMAND_VERSION, 3, WORKER),
                held(3, WORKER)
            ),
            Ok(()),
            "EXACTLY the ceiling is INSIDE the window; a `>=` ceiling refuses the only \
             version this build speaks"
        );

        let below = MIN_FENCED_COMMAND_VERSION.checked_sub(1).expect(
            "with a floor of 0 the UnfencedCommander arm is unreachable; that must be a loud \
             failure here, never a silently skipped case",
        );
        assert_eq!(
            fence_inbound_control_frame(command_at_version(below, 3, WORKER), held(3, WORKER))
                .unwrap_err(),
            ControlRefusal::UnfencedCommander {
                claimed_version: below
            }
        );

        let above = MAX_SUPPORTED_COMMAND_VERSION.checked_add(1).expect(
            "with a ceiling of u16::MAX the ProtocolTooNew arm is unreachable; that must be a \
             loud failure here, never a silently skipped case",
        );
        assert_eq!(
            fence_inbound_control_frame(command_at_version(above, 3, WORKER), held(3, WORKER))
                .unwrap_err(),
            ControlRefusal::ProtocolTooNew {
                claimed: above,
                supported: MAX_SUPPORTED_COMMAND_VERSION,
            }
        );
    }

    /// Distance above the ceiling changes nothing — including `u16::MAX`, the
    /// value a hostile peer reaches for and the one a ceiling written with
    /// wrapping arithmetic folds back inside the window.
    #[test]
    fn no_commander_above_the_ceiling_is_obeyed_however_far_above_it_lands() {
        let hostile: Vec<u16> = [2u16, 99, u16::MAX]
            .into_iter()
            .filter(|version| *version > MAX_SUPPORTED_COMMAND_VERSION)
            .collect();
        assert!(
            !hostile.is_empty(),
            "every surveyed value now sits INSIDE the window, so this case asserts nothing; \
             add one above MAX_SUPPORTED_COMMAND_VERSION rather than leaving a test that \
             passes by observing an empty loop"
        );
        for version in hostile {
            assert_eq!(
                fence_inbound_control_frame(
                    command_at_version(version, 3, WORKER),
                    held(3, WORKER)
                )
                .unwrap_err(),
                ControlRefusal::ProtocolTooNew {
                    claimed: version,
                    supported: MAX_SUPPORTED_COMMAND_VERSION,
                },
                "protocol version {version} was OBEYED by the shipped worker loop"
            );
        }
    }

    /// The two version refusals name OPPOSITE sides to move, and must stay
    /// distinguishable — the main-side fence's own defect class, held here.
    #[test]
    fn the_two_version_refusals_name_opposite_sides_to_move() {
        let too_old =
            fence_inbound_control_frame(command_at_version(0, 3, WORKER), held(3, WORKER))
                .unwrap_err();
        let too_new =
            fence_inbound_control_frame(command_at_version(u16::MAX, 3, WORKER), held(3, WORKER))
                .unwrap_err();
        assert_ne!(
            too_old.as_str(),
            too_new.as_str(),
            "one label for both makes the two populations indistinguishable in a dashboard"
        );

        let old_text = too_old.to_string();
        let new_text = too_new.to_string();
        assert!(
            old_text.contains("Upgrade the MAIN") && !old_text.contains("Upgrade the WORKER"),
            "an unfenced commander predates fencing, so the invocable action is to upgrade \
             the MAIN: {old_text}"
        );
        assert!(
            new_text.contains("Upgrade the WORKER") && !new_text.contains("Upgrade the MAIN"),
            "a too-new commander is ahead of this worker, so the action is to upgrade the \
             WORKER: {new_text}"
        );
        // The DIRECTIONS are the mirror of the main fence's, which is the point:
        // there, an unfenced peer means upgrade the SENDER (the worker) and a
        // too-new peer means upgrade the MAIN.
        assert!(
            new_text.contains(&u16::MAX.to_string())
                && new_text.contains(&MAX_SUPPORTED_COMMAND_VERSION.to_string()),
            "an operator holding one number cannot tell which side to move: {new_text}"
        );
    }

    #[test]
    fn a_command_for_another_attempt_is_refused_by_name() {
        let commanded = CommandedAttempt {
            assignment_id: other_attempt(),
            ..command(3, WORKER)
        };
        assert_eq!(
            fence_inbound_control_frame(commanded, held(3, WORKER)).unwrap_err(),
            ControlRefusal::WrongAttempt {
                commanded: other_attempt(),
                holding: attempt(),
            }
        );
    }

    /// THE THIRD HOLE. `fence.worker_id` was never read by the worker loop, so a
    /// stop addressed to `w-2` stopped `w-1`'s stage as long as the epoch matched.
    #[test]
    fn a_command_addressed_to_another_worker_is_refused() {
        assert_eq!(
            fence_inbound_control_frame(command(3, "w-2"), held(3, WORKER)).unwrap_err(),
            ControlRefusal::MisaddressedWorker {
                commanded: "w-2".to_string(),
                holding: WORKER.to_string(),
            }
        );
    }

    /// The address exemption, in BOTH directions — asserting only the pass would
    /// be indistinguishable from disabling the fence for unstamped assignments.
    #[test]
    fn an_unstamped_assignment_skips_only_the_address_check() {
        assert_eq!(
            fence_inbound_control_frame(command(3, "whoever"), held(3, "")),
            Ok(()),
            "an assignment that never reached the stamping seam must still be STOPPABLE; \
             refusing here makes its stage unreachable by any operator cancel"
        );
        assert_eq!(
            fence_inbound_control_frame(command(2, "whoever"), held(3, "")).unwrap_err(),
            ControlRefusal::StaleCommandGeneration {
                commanded: 2,
                holding: 3,
            },
            "but a superseded generation's command is still refused, so the exemption is \
             the address check alone and not the whole fence"
        );
    }

    /// The two generation refusals are SEPARATE, and the shipped worker loop had
    /// them merged into one `!=` with a `debug!` line.
    #[test]
    fn a_stale_and_an_unheld_generation_are_two_refusals_not_one() {
        let stale = fence_inbound_control_frame(command(2, WORKER), held(3, WORKER)).unwrap_err();
        let unheld = fence_inbound_control_frame(command(9, WORKER), held(3, WORKER)).unwrap_err();
        assert_eq!(
            stale,
            ControlRefusal::StaleCommandGeneration {
                commanded: 2,
                holding: 3,
            }
        );
        assert_eq!(
            unheld,
            ControlRefusal::UnheldCommandGeneration {
                commanded: 9,
                holding: 3,
            },
            "a command AHEAD of the held generation is not staleness; this worker has been \
             SUPERSEDED and must not be logged as holding a stale commander"
        );
        assert_ne!(stale.as_str(), unheld.as_str());
    }

    #[test]
    fn every_refusal_has_its_own_label() {
        let labels = [
            ControlRefusal::UnfencedCommander { claimed_version: 0 }.as_str(),
            ControlRefusal::ProtocolTooNew {
                claimed: 0,
                supported: 0,
            }
            .as_str(),
            ControlRefusal::WrongAttempt {
                commanded: attempt(),
                holding: attempt(),
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
        let mut unique = labels.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            labels.len(),
            "refusal labels must be distinct"
        );
    }

    /// The window is ONE number with the wire's.
    ///
    /// The main-side fence pins its own floor and ceiling to
    /// [`ATTEMPT_PROTOCOL_VERSION`] because bumping either alone fences the whole
    /// fleet out. The worker's window is the SAME contract read from the other
    /// end, so it needs the same pin or an upgrade moves one direction of the
    /// link and not the other. The cross-crate half —
    /// `the_two_fences_enforce_one_window` — lives in `kata-core`, the only
    /// crate that can see both.
    #[test]
    fn the_command_window_is_the_version_the_wire_announces() {
        assert_eq!(MIN_FENCED_COMMAND_VERSION, ATTEMPT_PROTOCOL_VERSION);
        assert_eq!(MAX_SUPPORTED_COMMAND_VERSION, ATTEMPT_PROTOCOL_VERSION);
    }

    /// The constructors read the SAME frame a worker actually holds, so the
    /// fence's inputs are the production ones rather than hand-built scalars.
    #[test]
    fn the_constructors_lift_the_coordinates_a_real_pair_of_frames_carries() {
        let assignment = capsule_at(7, WORKER);
        let assignment_id = assignment.attempt_id;
        let echoed = AttemptFence::echoing_capsule(&assignment);

        let honest = WorkerControl::Stop {
            assignment_id,
            fence: AttemptFence::commanding(7, SmolStr::new(WORKER)),
            reason: "operator asked".into(),
        };
        assert_eq!(
            fence_inbound_control_frame(
                CommandedAttempt::from_frame(&honest).unwrap(),
                HeldAttempt::holding(assignment_id, &echoed),
            ),
            Ok(()),
            "the main's own `AttemptFence::commanding` fence for the generation this worker \
             holds must pass; if it does not, production cannot cancel anything"
        );

        let superseded = WorkerControl::Stop {
            assignment_id,
            fence: AttemptFence::commanding(6, SmolStr::new(WORKER)),
            reason: "operator asked".into(),
        };
        assert_eq!(
            fence_inbound_control_frame(
                CommandedAttempt::from_frame(&superseded).unwrap(),
                HeldAttempt::holding(assignment_id, &echoed),
            )
            .unwrap_err(),
            ControlRefusal::StaleCommandGeneration {
                commanded: 6,
                holding: 7,
            }
        );
    }

    /// `HeldAttempt::holding` must read the ECHOED fence, so the coordinates a
    /// worker defends are the coordinates it reports. Two derivations is how a
    /// worker comes to refuse a command for the generation it is telling the
    /// main it is running.
    #[test]
    fn the_held_coordinates_are_the_ones_the_worker_echoes() {
        let capsule = capsule_at(4, WORKER);
        let echoed = echoed_at(4, WORKER);
        let held = HeldAttempt::holding(capsule.attempt_id, &echoed);
        assert_eq!(held.lease_epoch, capsule.lease_epoch);
        assert_eq!(held.worker_id, capsule.placed_on.as_str());
    }
}
