//! The two wall clocks one capsule attempt is held to, and the order between them that
//! holds by construction — with the two things it does not order.
//!
//! # The two clocks
//!
//! * The WORKER kills the container when the provider's frame budget ends: ONE deadline,
//!   [`PROVIDER_FRAME_MARGIN_MS`] past the capsule's own `wall_time_ms`, taken just before
//!   the `Assign` frame is written (`ProviderSupervisor::assign_stage`) and bounding the
//!   write, the acceptance and the terminal frame together — never a fresh budget per read.
//! * The MAIN settles a capsule attempt it has heard nothing more from once
//!   [`CAPSULE_WALL_TIME_GRACE_MS`] past `wall_time_ms` has elapsed since it FOLDED the
//!   worker's start checkpoint (`Dispatcher::sweep_capsule_wall_time`).
//!
//! The two anchors are different events. Between the start checkpoint and the assignment
//! the worker resolves the capsule and its environment, materializes the inputs, and
//! launches the provider through its handshake — an interval nothing bounded, so a slow
//! one let the main settle a live attempt that went on to succeed.
//!
//! # The bound that orders them, by construction
//!
//! The worker takes its PREPARE anchor BEFORE it sends the start checkpoint, and refuses
//! to hand the provider the assignment once [`CAPSULE_PREPARE_BUDGET_MS`] has passed since
//! (`kata_worker::oci_driver`'s `PrepareBudgetElapsed`, PROVEN NOT PERFORMED: nothing was
//! assigned) — checked before the provider's launch and again after its handshake, with no
//! suspension point between that last check and the instant the assignment's deadline is
//! taken. The main's anchor is its own clock when the checkpoint arrives, which is after it
//! was sent. So, with `A` the worker's anchor and `M ≥ A` the main's:
//!
//! ```text
//! worker kill issued  ≤  A + PREPARE + wall_time + FRAME_MARGIN
//!                     ≤  M + wall_time + GRACE − REPORT_SLACK
//! ```
//!
//! because [`CAPSULE_WALL_TIME_GRACE_MS`] is DEFINED as the sum of the three. So the kill is
//! issued at least [`CAPSULE_REPORT_SLACK_MS`] before the main may settle.
//!
//! # What this does NOT order
//!
//! * **The report of a stage that SUCCEEDED near its deadline.** A stage that completes
//!   just inside its frame budget is then published (its `/out` into the content store)
//!   and torn down before the worker reports it, and those steps have only the report
//!   slack to land in; a report later than the main's settlement is superseded by it (the
//!   settlement's verdict is PROVEN AMBIGUOUS and the late completion adopts nothing). The
//!   inequality orders the KILL, not a success's publication.
//! * **Two clocks that stop agreeing.** The worker measures on `CLOCK_MONOTONIC`
//!   (`std::time::Instant`), which does not advance while its host is SUSPENDED; the main
//!   measures the fold and the sweep on its wall clock (`now_ms`), which does, and which an
//!   operator or NTP may also step. A suspend of the worker's host, or a forward step of the
//!   main's wall clock between the fold and the sweep, shortens the main's interval against
//!   the worker's by its size — enough of either and the main settles a container the worker
//!   has not yet killed (the settlement's best-effort fenced stop then
//!   kills it).
//!
//! The budget values are policy, not measurements: the inequality holds for any values,
//! and each one only decides how slow a step may be before it is refused.

/// The slack a provider's frame budget carries past the stage's own wall clock: the
/// provider's own work around the stage (planning and starting the container before it
/// runs, killing and deleting it after), which the stage's clock does not include.
pub const PROVIDER_FRAME_MARGIN_MS: u64 = 30_000;

/// The longest a worker may spend between its capsule START anchor (taken before the
/// start checkpoint is sent) and handing the provider the assignment: resolving the
/// capsule and its environment, materializing up to the work-tree bounds, and launching
/// the provider through a handshake of up to 30 s. Past it the attempt is refused before
/// any container exists.
pub const CAPSULE_PREPARE_BUDGET_MS: u64 = 90_000;

/// How long the main waits, past the worker's kill being issued at the latest, before it
/// settles: the provider's kill and containment and the `Failed` report's transit — and,
/// for a stage that SUCCEEDED just inside its budget, its publication and teardown. It
/// bounds nothing — a report later than this is superseded by the settlement, which is
/// safe — it only lets the worker's own verdict land first in the ordinary case.
pub const CAPSULE_REPORT_SLACK_MS: u64 = 30_000;

/// The main's slack past a capsule's `wall_time_ms`, measured from the start it folded,
/// before it settles the attempt as lost — DERIVED, so the worker's kill is issued at least
/// [`CAPSULE_REPORT_SLACK_MS`] before it, on the module docs' two stated conditions (no
/// suspend of the worker's host, no step of the main's wall clock).
pub const CAPSULE_WALL_TIME_GRACE_MS: u64 =
    CAPSULE_PREPARE_BUDGET_MS + PROVIDER_FRAME_MARGIN_MS + CAPSULE_REPORT_SLACK_MS;
