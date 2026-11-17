//! The **local external-execution-provider** wire contract — the frames a
//! `ProviderSupervisor` and an external provider exchange, and the two
//! independent version numbers that version them.
//!
//! # Four words, four things, and this file is where blurring them would cost
//! the most
//!
//! * a **runtime** is the OCI runtime (the pinned youki) a provider drives to run
//!   a container. Nothing here is one.
//! * a **provider** is the external process kata does NOT link, which speaks
//!   the frames below.
//! * a **route** is `kata_worker::execution_route::OciRoute` — which mechanism a node uses
//!   for a stage. Decided before a single frame is written.
//! * a **supervisor** is `kata_worker::ProviderSupervisor` — the kata-side owner
//!   of one provider process: it installs the floor, spawns, admits or refuses
//!   the handshake, assigns, and tears down.
//!
//! # Why this is NOT `kata_transport::Envelope`
//!
//! The worker/attempt protocol already has a framed envelope, and reusing it was
//! considered and REJECTED on two checkable facts:
//!
//! 1. `crates/transport/conformance.toml` carries committed hashes over the
//!    `WorkerControl`/`WorkerMessage` shapes. A provider frame added to that
//!    type set moves those hashes for a protocol that has nothing to do with a
//!    worker dispatch, so an unrelated wire change would land as a conformance
//!    regeneration — the one edit
//!    `docs/architecture/0001-replacement-architecture.md` says must never be
//!    routine.
//! 2. `ATTEMPT_PROTOCOL_VERSION` and this protocol's number would then be forced
//!    into lockstep. The load-bearing rule for the provider's two numbers is
//!    that they *move independently*; folding a third number in with them
//!    would invert that.
//!
//! The cost is one length
//! rule and one JSON rule, both in this file, and the benefit is that a provider
//! author needs this crate's frame documentation and no Rust at all.
//!
//! # The frame
//!
//! ```text
//! [u32 big-endian body length][body: UTF-8 JSON]
//! ```
//!
//! Big-endian because it is the network order every language's standard library
//! spells without a flag. A declared length of `0` is a REFUSAL, not an empty
//! frame: an empty body decodes to no variant, so accepting it would mean
//! reading a frame that says nothing as though it said something. A declared
//! length above [`MAX_FRAME_BYTES`] is a refusal too — an unbounded length
//! prefix read from an untrusted peer is an allocation that peer chooses, which
//! is a bound a supervisor must hold itself.
//!
//! # Every decode is an EXHAUSTIVE DESTRUCTURE
//!
//! A field added to a frame must fail to COMPILE at
//! every consumer rather than be silently dropped. The types here are plain
//! structs with `#[serde(deny_unknown_fields)]`; the consumers
//! (`kata_worker::provider_supervisor` and `kata-provider-youki`) bind every
//! field by name in a `let Frame { .. } = frame;` destructure, which is `E0027`
//! the moment a field appears. `..` is forbidden by review in both.
//!
//! The field that shows why is [`AssignStage::plan`] — the container kata
//! described in full, which the provider must start exactly or refuse. A field
//! added beside it and absorbed with `..` would be an instruction kata considered
//! load-bearing that the provider silently dropped while answering `completed`.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TWO version numbers, and they are two TYPES so that one number is not
// expressible.
// ---------------------------------------------------------------------------

/// The **protocol** number: frame shapes and ordering.
///
/// A newtype rather than a bare `u16`, and that is *"the two numbers move
/// independently"* made structural. With two `u16` constants, an implementation
/// that used ONE number for both halves would be indistinguishable from this one
/// while both happened to read `1`; with two types it does not compile. There is
/// deliberately no conversion between this and [`CertificateVersion`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtocolVersion(pub u16);

/// The **certificate** number: the vocabulary of what a provider CLAIMS to
/// enforce.
///
/// Moves when [`ProviderCertificate`]'s meaning changes, never when a frame
/// changes: a provider may gain a containment property without a frame
/// changing, and a frame may change without any claim changing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CertificateVersion(pub u16);

/// The lowest protocol this build can speak.
///
/// **The floor equals the ceiling.** Every protocol bump changes a frame shape
/// an older peer's `deny_unknown_fields` decode would refuse, or reads a field
/// this build does not fill. Admitting such a peer at the handshake and
/// discovering the disagreement one frame later would report a malformed-frame
/// error for what is really a version mismatch — the ambiguity the two numbers
/// exist to avoid. So this build speaks exactly one protocol, and says so at the
/// door.
///
/// Each field below is on the wire because leaving it out — or giving it a
/// `#[serde(default)]` — would let a provider run something other than what kata
/// asked for while answering `completed`:
///
/// * [`AssignStage::plan`] — an assignment without its plan has nothing kata
///   asked the stage to run inside.
/// * `OciBundlePlan::state_root` — the OCI plan owns the directory the provider
///   writes beneath; a provider that defaulted it would choose where the bundle
///   and the runtime state land, and kata could not find them again.
/// * [`OciStdio`] — an AGENT is a long-lived process kata talks to rather than a
///   stage kata reads the output of afterwards, and the two need opposite stdio.
///   A defaulted field would decode an INTERACTIVE assignment as a captured one,
///   point the container's stdin at `/dev/null` and answer `accepted` — after
///   which kata would write a session handshake into a FIFO no process is
///   reading and wait out the whole wall budget.
/// * `OciBundlePlan::egress_hook` — an `Egress` capsule's
///   `hooks.createContainer` entries run as the RUNTIME's child inside the
///   container's network namespace, outside every bound the capsule's own
///   process is under; a provider that execs whatever hook path the bytes name,
///   without proving the bytes are the ones kata pinned, is the substitution
///   class `PinnedRuntime` exists for. A defaulted field would let an `Egress`
///   assignment read as hookless.
///
/// The assignment carries no program, argv, environment or working directory of
/// its own: the stage's are `process.args`, `process.env` and `process.cwd` inside
/// `OciBundlePlan::config_json`, and the binary the provider executes is the
/// plan's pinned runtime. Version 9 removed those four fields, so a version-8 peer
/// is refused at the handshake by its number rather than surfacing as an
/// undecodable frame.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(9);

/// The highest protocol this build can speak.
///
/// A peer above this is refused as [`ProviderRefusal::ProtocolTooNew`], whose
/// operator recourse is the OPPOSITE of
/// [`ProviderRefusal::ProtocolTooOld`]'s — upgrade the MAIN, not the provider.
pub const MAX_SUPPORTED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(9);

/// The certificate vocabulary this build understands.
///
/// Checked for EQUALITY, not for a ceiling, and the asymmetry with the protocol
/// number is deliberate: a protocol number bounds what kata can PARSE, so a peer
/// speaking an older-but-supported dialect is fine; a certificate number names
/// which claims mean what, so a certificate kata half-understands is a
/// certificate kata must not read at all.
///
/// The certificate number moves independently of the protocol number:
/// [`ProviderCertificate::measured_basis`] changed what a provider may CLAIM
/// while every frame shape stayed byte-identical. A certificate from an older
/// vocabulary is refused rather than read as *"a provider that announced no
/// basis"*, because those are different facts: one is a provider whose
/// vocabulary lacks the basis, the other a provider that has one to announce and
/// declined to. Likewise a vocabulary naming a basis axis this build does not
/// have is refused as a different vocabulary rather than decoded around the
/// field. Version 4 has one containment claim, `provider_enforced`: a
/// version-3 certificate could also claim `nothing_enforced`, and is refused
/// by its number.
pub const SUPPORTED_CERTIFICATE_VERSION: CertificateVersion = CertificateVersion(4);

/// The version a provider written against THIS source tree announces.
pub const PROTOCOL_VERSION: ProtocolVersion = MAX_SUPPORTED_PROTOCOL_VERSION;

/// The certificate vocabulary a provider written against THIS source tree uses.
pub const CERTIFICATE_VERSION: CertificateVersion = SUPPORTED_CERTIFICATE_VERSION;

/// The provider's half of the capture contract — see [`CaptureSpec`].
pub mod capture;

// ---------------------------------------------------------------------------
// The codec.
// ---------------------------------------------------------------------------

/// Bytes of big-endian length prefix in front of every body.
pub const FRAME_HEADER_BYTES: usize = 4;

/// The largest body this protocol will read or write.
///
/// 8 MiB. It bounds an allocation the PEER chooses, which is why it exists at
/// all; a stage's output is spooled to files ([`AssignStage::capture`]) and the
/// frame reports their sizes, so no amount of stage output can grow a body the
/// peer must refuse.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Why a frame could not be read or written.
///
/// Every arm is a REFUSAL with a name, never a default: this codec has no
/// "recovered by assuming" path, because a peer whose framing kata cannot follow
/// is a peer whose next byte kata cannot locate.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The declared body length was `0`. An empty body decodes to no frame, so
    /// accepting it would read silence as a message.
    #[error(
        "provider protocol: the peer declared a ZERO-byte frame body; an empty body is not a \
         frame and is refused rather than read as one"
    )]
    EmptyBody,
    /// The declared body length exceeded [`MAX_FRAME_BYTES`].
    #[error(
        "provider protocol: the peer declared a {declared}-byte frame body, above this build's \
         {ceiling}-byte ceiling; refusing rather than letting the peer choose kata's allocation"
    )]
    BodyTooLarge {
        /// What the peer's length prefix said.
        declared: usize,
        /// [`MAX_FRAME_BYTES`], carried so the message needs no second copy.
        ceiling: usize,
    },
    /// The stream ended where a frame was expected.
    #[error(
        "provider protocol: the peer closed the stream with no frame; a provider that exits \
         instead of answering is a crash, not an answer"
    )]
    PeerClosed,
    /// The body was not the JSON this protocol version defines.
    #[error("provider protocol: a frame body was not this protocol version's JSON: {0}")]
    Malformed(String),
    /// The underlying stream failed.
    #[error("provider protocol: frame I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Encode one frame: the 4-byte big-endian length followed by the JSON body.
///
/// # Errors
/// [`FrameError::Malformed`] if the value does not serialize, and
/// [`FrameError::BodyTooLarge`] if it serializes to more than
/// [`MAX_FRAME_BYTES`] — checked on the WRITE side too, so this build cannot
/// emit a frame it would refuse to read.
pub fn encode_frame<T: Serialize>(frame: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(frame).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::BodyTooLarge {
            declared: body.len(),
            ceiling: MAX_FRAME_BYTES,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::BodyTooLarge {
        declared: body.len(),
        ceiling: MAX_FRAME_BYTES,
    })?;
    let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + body.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// The body length a header declares, or the refusal it earns.
///
/// Split out of the read loop so the SYNC provider and the ASYNC supervisor
/// apply the same two bounds rather than each spelling them. A second spelling
/// of a ceiling is a ceiling that can disagree with itself.
///
/// # Errors
/// [`FrameError::EmptyBody`] and [`FrameError::BodyTooLarge`].
pub fn body_len(header: [u8; FRAME_HEADER_BYTES]) -> Result<usize, FrameError> {
    let declared = u32::from_be_bytes(header) as usize;
    if declared == 0 {
        return Err(FrameError::EmptyBody);
    }
    if declared > MAX_FRAME_BYTES {
        return Err(FrameError::BodyTooLarge {
            declared,
            ceiling: MAX_FRAME_BYTES,
        });
    }
    Ok(declared)
}

/// Decode one body.
///
/// # Errors
/// [`FrameError::Malformed`], carrying serde's own message — including the
/// `deny_unknown_fields` refusal, which is how an unrecognised field becomes a
/// refusal rather than a silent drop.
pub fn decode_frame<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    serde_json::from_slice(body).map_err(|e| FrameError::Malformed(e.to_string()))
}

/// Why the provider's OPENING frame was not accepted as a frame — see
/// [`decode_opening_frame`].
#[derive(Debug)]
pub enum OpeningFrameError {
    /// The body announced a hello whose version numbers this build refuses —
    /// the same refusal [`admit`] gives, reached before the body was decoded.
    Refused(ProviderRefusal),
    /// The body was not a frame this build can read at all.
    Malformed(FrameError),
}

/// Decode the provider's OPENING frame, judging a hello's two version NUMBERS
/// before its body.
///
/// A certificate from another vocabulary is, by definition, a body this build's
/// `deny_unknown_fields` types may not decode — an older vocabulary's measured
/// basis carries an axis this build does not have. Decoding the whole
/// frame first would report that peer as malformed, when what it is is a
/// provider speaking a vocabulary kata does not, which has a name. So the
/// numbers are read first, leniently (every other field ignored), and judged
/// by the same `judge_versions` [`admit`] applies; only a hello whose numbers
/// pass is decoded in full. A body that is not a hello, or whose numbers do not
/// read, falls through to the ordinary decode and its own error.
///
/// # Errors
/// [`OpeningFrameError::Refused`] — exactly `judge_versions`' refused set
/// (protocol below the floor, above the ceiling, or a certificate number that is
/// not [`SUPPORTED_CERTIFICATE_VERSION`]); [`OpeningFrameError::Malformed`] when
/// the body is not a frame this build reads.
pub fn decode_opening_frame(body: &[u8]) -> Result<ProviderFrame, OpeningFrameError> {
    /// The two numbers, and nothing else — no `deny_unknown_fields`, on purpose.
    #[derive(Deserialize)]
    struct Numbers {
        protocol_version: ProtocolVersion,
        certificate_version: CertificateVersion,
    }
    #[derive(Deserialize)]
    #[serde(tag = "kind", content = "frame", rename_all = "snake_case")]
    enum OpeningNumbers {
        Hello(Numbers),
    }
    if let Ok(OpeningNumbers::Hello(numbers)) = serde_json::from_slice::<OpeningNumbers>(body) {
        judge_versions(numbers.protocol_version, numbers.certificate_version)
            .map_err(OpeningFrameError::Refused)?;
    }
    decode_frame(body).map_err(OpeningFrameError::Malformed)
}

/// Write one frame to a blocking stream, flushing it.
///
/// # Errors
/// Whatever [`encode_frame`] and the stream produce.
pub fn write_frame<W: std::io::Write, T: Serialize>(
    out: &mut W,
    frame: &T,
) -> Result<(), FrameError> {
    out.write_all(&encode_frame(frame)?)?;
    out.flush()?;
    Ok(())
}

/// Read one frame from a blocking stream.
///
/// # Errors
/// [`FrameError::PeerClosed`] when the stream ends cleanly where a header was
/// expected — distinguished from a truncated header, which is an
/// [`FrameError::Io`] `UnexpectedEof` — plus everything [`body_len`] and
/// [`decode_frame`] refuse.
pub fn read_frame<R: std::io::Read, T: serde::de::DeserializeOwned>(
    input: &mut R,
) -> Result<T, FrameError> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    let mut filled = 0;
    while filled < FRAME_HEADER_BYTES {
        let n = input.read(&mut header[filled..])?;
        if n == 0 {
            if filled == 0 {
                return Err(FrameError::PeerClosed);
            }
            return Err(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "provider protocol: the stream ended inside a frame header",
            )));
        }
        filled += n;
    }
    let len = body_len(header)?;
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    decode_frame(&body)
}

/// Deserialize an `Option` field that must be PRESENT on the wire — `null` or a
/// value, never absent.
///
/// # This closes the hole `deny_unknown_fields` does not cover
///
/// The rule this protocol states for every field is that it *"arrived by a
/// protocol BUMP and not by a `#[serde(default)]`"*, and `deny_unknown_fields`
/// enforces the other direction — a field this build does not know is a refusal.
/// But serde treats an `Option<T>` field as OPTIONAL WITHOUT BEING ASKED: a body
/// that simply omits the key decodes to `None` with no attribute anywhere in
/// sight. Every `Option` on this wire means *"kata resolved none"* or *"the
/// provider has none"*, which is a decision — so an absent key would be read as a
/// decision nobody made. [`OciBundlePlan::egress_hook`] is the sharpest case:
/// omitted, an `Egress` capsule's plan would read as hookless, and its hooks would
/// be dropped while both sides answered `completed`.
///
/// Naming a `deserialize_with` makes serde require the key, because it can no
/// longer assume the field's own `Default`. `a_present_null_and_an_absent_key_are_different_frames`
/// is the pin.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// ---------------------------------------------------------------------------
// The frames.
// ---------------------------------------------------------------------------

/// Everything the SUPERVISOR sends.
///
/// Adjacently tagged (`{"kind": …, "frame": {…}}`) rather than internally
/// tagged, because an internally tagged variant is deserialized from a map that
/// still contains the tag, so `deny_unknown_fields` on the payload would reject
/// `kind` itself. Adjacent tagging keeps BOTH properties: a self-describing wire
/// and a payload that refuses a field this build does not know.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "frame", rename_all = "snake_case")]
pub enum SupervisorFrame {
    /// Start the container the frame's plan describes. The only supervisor
    /// frame.
    Assign(AssignStage),
}

/// Everything the PROVIDER sends.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "frame", rename_all = "snake_case")]
// `Hello` (the certificate) dwarfs the three work frames — boxing it would make the
// handshake allocate for a savings the common case (Completed, 56 bytes) never pays.
#[allow(clippy::large_enum_variant)]
pub enum ProviderFrame {
    /// The provider's opening frame: its two numbers and its certificate. Sent
    /// unprompted, before it reads anything, so a supervisor learns what it is
    /// talking to before it hands over work.
    Hello(ProviderHello),
    /// The provider has taken the assignment and is about to run it. **This is
    /// the frame a crash proof must have OBSERVED before it may kill
    /// anything** — without it, *"the provider died and
    /// kata coped"* is satisfiable by a provider that never started.
    Accepted(AssignmentAccepted),
    /// The stage ran to completion (successfully or not).
    Completed(StageCompleted),
    /// The provider itself refused the assignment. Distinct from
    /// [`Self::Completed`] with a non-zero exit: nothing ran.
    Refused(AssignmentRefused),
}

/// Where a provider leaves a stage's captured output, and how much it may leave.
///
/// Captures are FILES, not frame bytes: [`AssignStage::capture`] names this and
/// [`StageCompleted`] reports sizes rather than payloads. A frame can never
/// outgrow [`MAX_FRAME_BYTES`] on account of a stage's output, because the frame
/// carries four small fields and the bytes live on the filesystem the supervisor
/// owns.
///
/// # The spool directory
///
/// An ABSOLUTE path the supervisor created EMPTY under the attempt root, with
/// the same rules [`InteractiveStdio`]'s FIFO paths carry: not relative (it would
/// resolve against wherever the provider was started), no `..` component (which
/// can name a directory outside the attempt the worker owns while every character
/// of the path looks ordinary). The provider writes exactly
/// `<spool_dir>/stdout` and `<spool_dir>/stderr`, each opened
/// `O_EXCL | O_NOFOLLOW`: a name that already exists, or resolves through a
/// link, is a refusal rather than a write over bytes that are not this stage's.
/// What already lives in the directory is not the provider's business — the
/// supervisor gave it an empty one.
///
/// # The bound is COMBINED, and breaching it KILLS
///
/// `limit_bytes` bounds `stdout` and `stderr` TOGETHER — one capture bound for
/// every route a stage can take. A stage whose
/// two spool files sum past it is a stage nobody can safely answer for — its
/// `content` would be a claim about bytes that were dropped — so the provider
/// kills the process it spawned through the same path a wall-time or a cancel
/// uses, reports [`StageCompleted::capture_exceeded`], and never reports
/// `completed` for output it had to stop collecting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSpec {
    /// The absolute, supervisor-created, empty directory the two spool files
    /// live under. See the type docs for the refused set.
    pub spool_dir: String,
    /// The COMBINED byte bound over both streams; breaching it kills the stage
    /// and sets [`StageCompleted::capture_exceeded`].
    pub limit_bytes: u64,
}

/// The supervisor's assignment: the rootless OCI container kata already
/// described in full, and where its captured output goes.
///
/// # No program, argv, environment or working directory of its own
///
/// A stage's argv, environment and working directory are `process.args`,
/// `process.env` and `process.cwd` inside [`OciBundlePlan::config_json`], and the
/// binary the provider executes is the plan's pinned runtime
/// ([`OciBundlePlan::youki`]). A second copy on the frame could only disagree with
/// the plan, so there is none, and a peer that sends one is refused at decode by
/// `deny_unknown_fields`.
///
/// # Every field arrived by a protocol BUMP and not by a `#[serde(default)]`
///
/// [`Self::plan`] is why: a provider that decoded an assignment without its plan
/// would have nothing kata asked the stage to run inside, and running the stage
/// anyway would be containment silently degraded to none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignStage {
    /// The protocol the supervisor is speaking. Echoed on the frame rather than
    /// held only in the handshake so a provider reading a single frame out of a
    /// log can tell what it is looking at.
    pub protocol_version: ProtocolVersion,
    /// Opaque to the provider; echoed back on every answering frame so an answer
    /// about a different assignment is a refusal rather than a mis-attribution.
    pub assignment_id: String,
    /// The container to start.
    ///
    /// `bin/kata-provider-youki` is its one applier. A provider that cannot apply
    /// it exactly must answer [`ProviderFrame::Refused`]: running the stage anyway
    /// would be a containment plan silently degraded to none.
    pub plan: OciBundlePlan,
    /// Where the stage's captured stdout and stderr are written, and the
    /// combined bound over them. Every assignment carries one, even the
    /// `interactive` OCI arm where nothing is spooled: a provider that cannot
    /// honor it there leaves the directory empty, reports zero sizes, and is
    /// expected to — the field's presence is not a claim that bytes were
    /// captured, only a place they would land.
    pub capture: CaptureSpec,
}

/// A rootless OCI container kata has ALREADY DESCRIBED, as the bytes a provider
/// needs to start it.
///
/// # Every field is something kata decided, and the provider decides nothing
///
/// This carries the `config.json` BYTES `kata_worker::oci_bundle::spec_for`
/// produced, so a provider running it makes no containment choice. A provider that built a spec from a policy
/// description would be a second implementation, and a cross-driver comparison
/// against it would be measuring THAT rather than the wire.
///
/// It is the only plan: the assignment carries it untagged, so a peer that sends
/// any other kind of plan is refused when the frame is decoded.
///
/// # THE STAGE FENCE THIS PLAN CARRIES IS ENFORCED — measured
///
/// **MEASURED** on the pinned youki 0.7.0 from `nix/youki.nix` (the libseccomp
/// build, store path `…-youki-seccomp-0.7.0`), inside a real container started from
/// these bytes:
///
/// ```text
/// /proc/self/status -> Seccomp: 2   Seccomp_filters: 1
/// ```
///
/// one filter, with no kata floor installed, from the deny-list entries in
/// [`Self::config_json`]. `crates/worker/tests/oci_provider_live.rs`'s floor test
/// is the observation, and `crates/worker/tests/oci_adversarial_live.rs`'s A1' row
/// is the per-syscall consequence: `unshare` inside such a container is refused.
///
/// **A youki built without libseccomp applies no filter at all rather than
/// refusing the section** — measured: a container carrying every deny-list entry
/// reported `Seccomp_filters: 0`. Two things make the claim above safe:
/// `oci_runtime::fold_seccomp_support` turns a missing `libseccomp:` line in
/// `youki --version` into a NAMED refusal (`SeccompUnsupported`), and the pin is
/// a build that has one. So a host that cannot enforce this fence cannot
/// certify at all.
///
/// `youki features` is NOT the witness for this and never was: youki 0.7.0 reports
/// `"seccomp": null` there on a libseccomp build and a non-libseccomp build alike
/// (both measured; its `features.rs` carries a literal
/// `// TODO: Expose seccomp support information`). The witness is the `libseccomp:`
/// line in `--version`, which is what `certify_youki` reads — see
/// `kata_worker::oci_runtime`'s own header for why.
///
/// # The floor does NOT ride here, and there is no field it could ride in
///
/// The kata seccomp floor's entire security value is that the provider
/// cannot decline it, so it must never ride a frame a provider could drop. That
/// holds here by CONSTRUCTION rather than by a check: this struct has no
/// seccomp-bytes field at all (`the_oci_plan_carries_no_filter_bytes_field`). The container's own syscall fence is inside
/// [`Self::config_json`] as the OCI spec's `linux.seccomp` — the STAGE fence,
/// every entry of kata's stage deny-list (`kata_types::sandbox_seccomp::DENIED_SYSCALLS`,
/// named in prose because this crate is a leaf) — and the floor stays
/// where it belongs, installed by kata on itself before the provider is
/// `execve`d. `crates/worker/tests/oci_bundle_golden.rs` observes both halves.
///
/// # Why paths are `String` and not a kata type
///
/// This crate is an ABSOLUTE LEAF (see its `Cargo.toml`): a third party must be
/// able to implement the protocol from the frame table alone, so it may never
/// gain `kata-types`. The guest paths in [`Self::rootfs_mountpoints`] are
/// `kata_types::execution_contract::GuestPath` values on kata's side of the
/// boundary and are validated there; what crosses the wire is their text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciBundlePlan {
    /// The whole `config.json`, as the exact text a provider writes into the
    /// bundle directory unchanged.
    ///
    /// TEXT and not a parsed structure: what kata planned is a byte sequence, and a provider that re-serialized a parsed form could change key
    /// order, number formatting or an unknown field and still answer `completed`.
    /// The provider writes these bytes; a provider that cannot must refuse.
    ///
    /// # Why `String` and not `Vec<u8>`
    ///
    /// A `Vec<u8>` encodes on this JSON wire as an ARRAY OF NUMBERS, which made
    /// two things worse at once: the frame roughly quintupled for no gain, and a
    /// test searching the serialized plan for arbitrary byte sequences became
    /// VACUOUS here,
    /// because no byte sequence can appear in that encoding as itself. A
    /// `config.json` is UTF-8 by the OCI spec's own definition, so `String` is
    /// the type that says so, and the structural guarantee that this plan carries
    /// no filter channel is made by its FIELD SET
    /// (`the_oci_plan_carries_no_filter_bytes_field`) rather than by a search.
    pub config_json: String,
    /// Absolute GUEST directories the provider must create inside the rootfs
    /// before starting the container, in the order kata resolved them.
    ///
    /// A rootless bundle's rootfs is an EMPTY tree of mountpoints — every byte a
    /// stage can read arrives as a mount named in [`Self::config_json`] — and a
    /// missing mountpoint is a mount youki refuses rather than a mount that
    /// silently lands elsewhere. Carried explicitly because it is kata's answer
    /// to *"what does the rootfs contain"*, and a provider that derived it by
    /// re-parsing the config would be answering that question itself.
    pub rootfs_mountpoints: Vec<String>,
    /// The container identity the provider passes to `run` / `kill` / `delete`.
    ///
    /// Distinct from [`AssignStage::assignment_id`] on purpose: this one is the
    /// runtime's own namespace and collides with any other container of the same
    /// name on the host.
    pub container_id: String,
    /// The runtime binary kata PINNED and measured, so the provider can prove it
    /// is about to exec the same bytes.
    pub youki: PinnedRuntime,
    /// The KATA-OWNED parent cgroup the container's own leaf is created beneath,
    /// or `None` when kata measured no delegated parent to own one under.
    ///
    /// # What a `Some` means, and why it is not advice
    ///
    /// Kata created this directory, wrote this stage's `memory.max`,
    /// `memory.swap.max` and `pids.max` on it, and enabled the controllers its
    /// children need. [`Self::config_json`]'s `linux.cgroupsPath` names a leaf
    /// BENEATH it, so the runtime's own cgroup is inside a subtree kata owns,
    /// accounts and sweeps — which is what makes a supervisor's abrupt teardown
    /// (`kata_worker::provider_supervisor::ProviderSupervisor::kill_and_contain`)
    /// reach the container at all.
    ///
    /// **MEASURED on the reference host, and it is the whole reason this field
    /// is never `None` in production:** with `linux.cgroupsPath` unset, youki
    /// 0.7.0 asks the user manager for its own transient `youki-<id>.scope`, the
    /// container's init lands OUTSIDE any subtree kata owns, and a `SIGKILL` on the
    /// provider leaves it `Running` while kata's `TeardownProbe::CgroupPopulation`
    /// reads an empty provider subtree and scores `Confirmed`. A `Some` here is
    /// what closes that.
    ///
    /// # `None` is refused by `kata-provider-youki`, and that is the mechanism
    ///
    /// `None` is *"kata measured no delegated parent"*, never *"place it
    /// anywhere"*. On this route it leaves the runtime to pick its own cgroup,
    /// which is precisely the leak above, so the provider REFUSES it rather than
    /// starting a container nothing can tear down: a bound kata planned is never
    /// silently lost at the boundary.
    #[serde(deserialize_with = "required_option")]
    pub cgroup_parent: Option<String>,
    /// The ATTEMPT-LOCAL directory the provider writes the bundle and the runtime
    /// state tree beneath. Absolute, `..`-free, worker-local.
    ///
    /// # Not the stage's working directory
    ///
    /// The stage's working directory is `process.cwd` inside
    /// [`Self::config_json`]; this is the provider's own scratch root, which is a
    /// different question with a different answer, so the two are never one
    /// field.
    ///
    /// # Refused by the provider
    ///
    /// Not absolute (a relative path resolves against wherever the provider
    /// happens to have been started, so the bundle and the state tree would land
    /// somewhere kata does not know to look, and a container whose state kata
    /// cannot find can be neither torn down nor read back); containing a `..`
    /// component (which could name a directory outside the attempt the worker
    /// owns). The provider does NOT refuse an existing state root —
    /// `youki --root <dir> <anything>` creates that directory, a read-only `youki state` from a
    /// host observer included, so a freshness check there would refuse for being
    /// watched. The freshness check is on the BUNDLE directory.
    pub state_root: String,
    /// WHERE the container init's three standard descriptors come from.
    ///
    /// The field exists because the agent plane needs the OPPOSITE of what a
    /// shell stage needs, and neither answer can be a default — see
    /// [`OciStdio`].
    pub stdio: OciStdio,
    /// The `kata-oci-hook` binary kata pinned for an `Egress` capsule's
    /// `hooks.createContainer` entries — `None` on an `Offline` plan, which
    /// carries no hooks at all.
    ///
    /// # The two halves must agree, and the provider is where it is checked
    ///
    /// A `createContainer` hook runs as the RUNTIME's child — inside the
    /// container's network namespace but on the host's mount namespace, with
    /// the runtime's own capabilities — which is code execution OUTSIDE every
    /// bound the capsule's own `CapEff=0` init is under. So
    /// `kata-provider-youki` refuses each disagreement the pair can carry:
    /// hooks rendered where the plan says `None`, a `Some` whose
    /// `config.json` registers no `createContainer` entries, a `createContainer`
    /// `path` that is not this binary, an entry on any hook phase kata does not
    /// render, and — `hook_digest_mismatch` — bytes at `store_path` that do not
    /// hash to `sha256`.
    ///
    /// `required_option` rather than serde's silent `Option` default, for the
    /// reason every field here carries it: a plan that omitted the key would
    /// decode as `None`, and an egress capsule would start with its hooks
    /// silently dropped.
    #[serde(deserialize_with = "required_option")]
    pub egress_hook: Option<PinnedRuntime>,
}

/// How a container init's `stdin`, `stdout` and `stderr` are connected.
///
/// # Two callers, two opposite needs, and why a default would be wrong for one of
/// them
///
/// A SHELL STAGE is a one-shot: kata starts it, it prints, it exits, and kata reads
/// what it printed off the spool files [`AssignStage::capture`] names. Its stdin must be empty (the
/// provider is still serving this protocol on its own) and its output must go to
/// FILES rather than pipes, which is a measured lesson — a piped
/// descriptor is inherited by the container's init, so a read-to-EOF on this side
/// blocks until that process closes it, which a hung container never does, and the
/// teardown after the read never runs. That is [`Self::Captured`].
///
/// An AGENT is a long-lived peer: kata speaks a line-framed protocol to it for the
/// whole attempt, so the bytes must flow WHILE the container runs, in both
/// directions. [`StageCompleted`]'s capture SIZES are then all zero — the
/// bytes were consumed by kata's codec as they arrived and were never a file.
/// That is [`Self::Interactive`].
///
/// # MEASURED on the reference host, and it is why this is a FIFO pair
/// rather than a new pair of byte frames
///
/// `youki run` with `process.terminal = false` gives the container's init the
/// RUNTIME CLIENT's own three descriptors: a throwaway rootless bundle running
/// `busybox cat` echoed `hello-from-host` back on the client's stdout after the host
/// wrote that line to the client's stdin, and closing the client's stdin gave `cat`
/// its EOF and a clean exit `0`. So live stdio needs no PTY, no `youki exec` and no
/// socket inside the capsule — it needs the provider to hand the client three
/// descriptors that reach kata, and three FIFOs KATA NAMED are the smallest way to
/// do that without teaching this request/response protocol to interleave byte frames
/// with an assignment in flight.
///
/// The alternative measured and rejected in the same session: `youki exec` into the
/// running container fails `EPERM` under rootless on this host (`failed to set
/// namespace … typ: Pid`), so a SECOND process cannot be added to a container this
/// route started — which is why kata's agent plane declares terminal callbacks
/// unsupported on this route rather than serving them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "io", rename_all = "snake_case")]
pub enum OciStdio {
    /// `stdin` is `/dev/null`; `stdout` and `stderr` are the two spool files
    /// beneath [`AssignStage::capture`]'s `spool_dir`, whose sizes the provider
    /// reports on [`StageCompleted`] and whose bytes kata reads back itself.
    Captured,
    /// `stdin`, `stdout` and `stderr` are the three FIFOs kata created and named.
    ///
    /// [`StageCompleted::stdout_bytes`] and [`StageCompleted::stderr_bytes`] are
    /// then `0` and [`StageCompleted::capture_exceeded`] is `false`, because
    /// nothing was captured to a file: kata read every byte as it was produced.
    /// A provider that reported anything else would be reporting bytes it does
    /// not have.
    Interactive(InteractiveStdio),
}

impl OciStdio {
    /// Stable snake_case token — the log field and the quoted word in a refusal.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Interactive(_) => "interactive",
        }
    }
}

/// The three FIFOs kata created for a live container's stdio.
///
/// # Kata names them, kata creates them, and the provider only OPENS them
///
/// Three paths rather than one directory: a provider handed a directory would have to derive three names inside it, which is
/// a second producer of a fact only kata should produce. Three explicit paths make a
/// renamed FIFO a refusal on the provider's own `open` rather than a container whose
/// output goes somewhere nobody is reading.
///
/// Kata creates them BEFORE it assigns, and that ordering is load-bearing: opening
/// one end of a FIFO blocks until the other end appears, so both sides have to be
/// able to open without waiting for each other. Kata opens its own ends first
/// (`O_RDWR` for the stdin it writes, so the pipe has a reader from the start and the
/// provider's open cannot block; `O_RDONLY | O_NONBLOCK` for the two it reads, so the
/// open returns at once rather than waiting for a writer that cannot exist yet), and
/// only then writes the assignment.
///
/// A non-blocking OPEN is not a non-blocking READ, and the difference decides the
/// ordering on the other side: a read-only FIFO whose writer has not opened yet reads
/// as a clean END-OF-FILE, not `EAGAIN`. So on this arm a provider must open the two
/// write ends and start the container BEFORE it answers `accepted` — kata reads as
/// soon as it has that frame, and an acceptance sent earlier would let kata observe
/// the vendor's stream ending before its first byte.
///
/// # Refused by the provider
///
/// A path that is not absolute or carries a `..` component (the state root's rules,
/// for the state root's reasons), and a path that is not ALREADY a FIFO — because a
/// provider that created a missing one would be choosing where a container's output
/// goes, and one that opened a regular file there would connect the container to
/// bytes on disk while kata waited on a pipe.
///
/// # What this deliberately is NOT
///
/// Not a PTY: no terminal is allocated on either side, `process.terminal` stays
/// `false`, and no vendor gets a tty to draw on. Not host stdio: these are three
/// FIFOs under the attempt directory the worker owns, never a descriptor inherited
/// from kata's own stdin/stdout/stderr. Not an environment channel: the
/// assignment has no environment field at all, so nothing about the vendor's
/// context arrives this way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractiveStdio {
    /// The FIFO kata WRITES and the container init reads as its `stdin`.
    pub stdin_fifo: String,
    /// The FIFO the container init writes as its `stdout` and kata reads.
    pub stdout_fifo: String,
    /// The FIFO the container init writes as its `stderr` and kata reads.
    pub stderr_fifo: String,
}

/// The container runtime kata pinned, by PATH and by CONTENT.
///
/// Both, because either alone is a different and weaker claim: a path says which
/// file will be `execve`d and nothing about its bytes, and a digest says which
/// bytes without saying that they are the ones on disk at that path. A provider
/// re-derives the digest of [`Self::store_path`] and refuses a mismatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedRuntime {
    /// The exact, absolute, resolved path of the runtime executable.
    pub store_path: String,
    /// sha256 of that file's bytes, lowercase hex, as `sha256sum` prints it.
    pub sha256: String,
}

/// `kernel.apparmor_restrict_unprivileged_userns` as KATA READ IT, in the
/// certificate's own closed vocabulary.
///
/// Three arms because the read has three outcomes and the third is not a
/// synonym for either answer: an unreadable or unparsable knob is `unknown`, and
/// folding it into `unrestricted` would report a host as permissive on the
/// strength of a file kata could not open. Mirrors
/// `kata_worker::oci_runtime::UsernsRestriction`, spelled again here because this
/// crate is an absolute leaf and may never gain `kata-worker` — the two are
/// bound by the mapping in `kata_worker::provider_supervisor` and by nothing
/// else.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasuredUsernsRestriction {
    /// Non-zero: an unprofiled binary transitions into `unprivileged_userns`.
    Restricted,
    /// Zero: no profile is needed for the userns transition.
    Unrestricted,
    /// Unreadable or unparsable. Never reported as either answer.
    Unknown,
}

impl MeasuredUsernsRestriction {
    /// Stable snake_case token — the wire value and the log field.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            MeasuredUsernsRestriction::Restricted => "restricted",
            MeasuredUsernsRestriction::Unrestricted => "unrestricted",
            MeasuredUsernsRestriction::Unknown => "unknown",
        }
    }
}

/// **What KATA measured about the rootless-OCI mechanism, as the bytes a provider
/// may quote back and nothing else.**
///
/// # This type is what makes [`ClaimedContainment::ProviderEnforced`] admissible
/// at all
///
/// Without a basis that claim is refused outright, on the ground that *"kata
/// has measured NOTHING about a process it does not link"*. The refusal is not
/// about the claim being unthinkable — such a provider is admitted by ADDING a
/// kata measurement, never by relaxing the refusal — it is about kata having no
/// measurement to compare it against.
/// `kata_worker::oci_runtime::certify_youki` is that measurement, and this is
/// its wire form.
///
/// # A provider can only ECHO it, by construction
///
/// The supervisor hands these bytes to the provider on its ARGV
/// (`--measured-basis <json>`, see
/// `kata_worker::provider_supervisor::provider_command_prefix`), and [`admit`]
/// admits the claim only when the certificate's copy is BYTE-EQUAL to the basis
/// kata measured on this host in this process. So a provider cannot invent a
/// basis, cannot improve one, and cannot carry one forward from an earlier host:
/// the only certificate that passes is one restating what kata already knows. A
/// basis is therefore never evidence ABOUT the provider — it is evidence about
/// kata's own runtime, which the provider has acknowledged it is running under.
///
/// # Why argv and not a frame
///
/// [`ProviderFrame::Hello`] is written *before the provider reads anything* —
/// that ordering is what lets a supervisor learn what it is talking to before it
/// hands over work, and `ProviderSupervisor::launch` refuses any opening frame
/// that is not a hello. A basis delivered as a supervisor frame would have to be
/// read BEFORE the hello, inverting that. Argv also keeps the basis out of the
/// environment, where an operator could set it: a fault-injectable input is
/// never read from the environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OciMeasuredBasis {
    /// The runtime kata pinned, by PATH and by CONTENT — the same pair
    /// [`OciBundlePlan::youki`] carries, re-derived by the certification from the
    /// bytes on disk.
    pub youki: PinnedRuntime,
    /// The `(major, minor, patch)` the binary itself REPORTED, dotted. A string
    /// rather than a triple because this basis is compared for byte-equality and
    /// never ordered: the version FLOOR was applied by the certification that
    /// produced this, and re-deciding it here would be a second, weaker copy of
    /// that check.
    pub youki_version: String,
    /// The libseccomp version the pinned runtime REPORTED being built against,
    /// verbatim — the witness `kata_worker::oci_runtime::fold_seccomp_support`
    /// refused the certification without.
    ///
    /// A string and not a `bool`, for [`Self::functional_probe_id`]'s reason: a
    /// `true` would be kata's own conclusion about the line, and this is the value
    /// the binary printed. `"unknown"` is a legitimate value here and is carried
    /// as measured — youki's `build.rs` emits it when
    /// `pkg_config::probe_library("libseccomp")` fails WITH the feature already
    /// on, so it means *"reads `linux.seccomp`, could not name its libseccomp"*
    /// and not *"we did not look"*. Never ordered and never compared against a
    /// floor: which libseccomp is new enough is a question nobody here has asked.
    ///
    /// The axis is not redundant with [`Self::youki`]'s sha256. It is what makes
    /// [`Self::residue_denied`]'s *"kata's fence NAMES all 13"* separable from
    /// *"a runtime that READS them"*. Before the re-pin the two were measurably
    /// different facts — youki 0.7.0 from `nixpkgs#youki` was built without
    /// `libcontainer/libseccomp` and dropped the whole section in silence — and a
    /// certificate echoed from such a host must not be admissible against a basis
    /// measured on one that has it.
    pub libseccomp_version: String,
    /// The AppArmor profile NAME the kernel's loaded list is keyed by.
    pub apparmor_profile_name: String,
    /// sha256 of the INSTALLED profile text at `/etc/apparmor.d/<name>`, as the
    /// certification read it.
    ///
    /// The name alone says a profile with that name is loaded; this says which
    /// TEXT is installed under it, and the text is the only place the name is
    /// bound to the pinned executable's path. Both, for [`PinnedRuntime`]'s
    /// reason — either alone is a weaker claim wearing the same words.
    pub apparmor_profile_sha256: String,
    /// The kernel restriction, as read. Recorded and never refused on: see
    /// `kata_worker::oci_runtime::UsernsRestriction`.
    pub userns_restriction: MeasuredUsernsRestriction,
    /// The delegated parent cgroup directory kata MEASURED as usable, or `None`
    /// when it measured none.
    ///
    /// `None` is a measurement (*"this host delegates nothing kata could use"*),
    /// never an unattempted probe — `measure_cgroup_delegation` creates, writes
    /// and removes a child before it answers.
    #[serde(deserialize_with = "required_option")]
    pub delegated_cgroup_parent: Option<String>,
    /// The container id of the throwaway rootless container the certification
    /// actually RAN.
    ///
    /// The one axis no read substitutes for, carried as the identity of the run
    /// rather than as a boolean: a `true` would be a claim, and this is a
    /// pointer at the container whose exit status was observed.
    pub functional_probe_id: String,
    /// Whether the fence kata plans for this route DENIES all 13
    /// `ConstructionResidue` syscalls.
    ///
    /// **This is a fact about kata's own deny list, not an observation from
    /// inside a container.** `kata_types::sandbox_seccomp::oci_seccomp_rules`
    /// renders every entry of `DENIED_SYSCALLS`, residue included, so kata can
    /// say the rule is present; that the kernel returns `EPERM` for each of them
    /// in a running container is the adversarial A1' row's observation and is
    /// NOT claimed here.
    ///
    /// A `true` here therefore means *"kata's OCI fence NAMES all 13"* and nothing
    /// about what the kernel does with them — which is why the axis belongs in a
    /// MEASURED BASIS at all: it is a fact about the plan kata produced, on the same
    /// footing as the digest of the runtime that will read it.
    ///
    /// **What the kernel does with them is measured too, elsewhere, and it
    /// agrees.** The fence is enforced under the current pin (see
    /// [`OciBundlePlan`]'s own section for the libseccomp condition), and
    /// `crates/worker/tests/oci_adversarial_live.rs`'s A1' row is
    /// where that is asserted per syscall rather than here — the separation is the
    /// point: this field stays a statement about the PLAN even when the plan happens
    /// to be enforced, because a basis a provider echoes must not depend on an
    /// observation the provider could not make.
    /// It does not weaken
    /// [`ProviderCertificate::declares_construction_residue_unverified`], which
    /// stays `true` on every certificate: that declaration is about kata never
    /// verifying the PROVIDER's residue handling, and a rule in kata's own spec is
    /// not that verification.
    pub residue_denied: bool,
}

impl OciMeasuredBasis {
    /// The field names on which `self` and `other` differ, for a refusal that
    /// names the disagreement instead of printing two structs.
    ///
    /// EXHAUSTIVE DESTRUCTURE of both sides — a field added to this struct is
    /// `E0027` here, so a new axis cannot be compared by `PartialEq` and then go
    /// unnamed in the one message an operator reads.
    #[must_use]
    pub fn differing_fields(&self, other: &Self) -> Vec<&'static str> {
        let Self {
            youki,
            youki_version,
            libseccomp_version,
            apparmor_profile_name,
            apparmor_profile_sha256,
            userns_restriction,
            delegated_cgroup_parent,
            functional_probe_id,
            residue_denied,
        } = self;
        let Self {
            youki: other_youki,
            youki_version: other_version,
            libseccomp_version: other_libseccomp,
            apparmor_profile_name: other_profile_name,
            apparmor_profile_sha256: other_profile_sha256,
            userns_restriction: other_userns,
            delegated_cgroup_parent: other_parent,
            functional_probe_id: other_probe,
            residue_denied: other_residue,
        } = other;
        let mut differing = Vec::new();
        if youki.store_path != other_youki.store_path {
            differing.push("youki.store_path");
        }
        if youki.sha256 != other_youki.sha256 {
            differing.push("youki.sha256");
        }
        if youki_version != other_version {
            differing.push("youki_version");
        }
        if libseccomp_version != other_libseccomp {
            differing.push("libseccomp_version");
        }
        if apparmor_profile_name != other_profile_name {
            differing.push("apparmor_profile_name");
        }
        if apparmor_profile_sha256 != other_profile_sha256 {
            differing.push("apparmor_profile_sha256");
        }
        if userns_restriction != other_userns {
            differing.push("userns_restriction");
        }
        if delegated_cgroup_parent != other_parent {
            differing.push("delegated_cgroup_parent");
        }
        if functional_probe_id != other_probe {
            differing.push("functional_probe_id");
        }
        if residue_denied != other_residue {
            differing.push("residue_denied");
        }
        differing
    }
}

/// The provider's opening frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHello {
    /// The first number: frame shapes and ordering.
    pub protocol_version: ProtocolVersion,
    /// The second number. Independent of the first by TYPE, so a build cannot
    /// accidentally ship one number wearing two names.
    pub certificate_version: CertificateVersion,
    /// What the provider CLAIMS. Never what kata measured.
    pub certificate: ProviderCertificate,
}

/// What a provider claims about itself — **a CLAIM, and the type says so in its
/// own documentation because nothing about it is a kata measurement.**
///
/// A claimed fact and a measured fact are different types. This is the claimed
/// side of that pair for an external provider: the supervisor
/// may quote it, print it, and refuse on it, and it may never fold it into
/// anything an operator reads as a containment kata established. The one fact
/// kata MEASURES about a provider is the floor it installed before `execve`,
/// which is not on this certificate because the provider does not get a say in
/// it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCertificate {
    /// The name the provider calls itself. Checked against the operator's
    /// declared `KATA_EXTERNAL_EXECUTION_PROVIDER` value: a binary that answers
    /// to one name and announces another is a substitution, and is refused.
    pub provider: String,
    /// What the provider claims to enforce.
    pub containment: ClaimedContainment,
    /// **Unverified residue, on the certificate's own face.** The 13
    /// `ConstructionResidue` syscalls are structurally unverifiable from kata's
    /// side, so a certificate must SAY kata did not verify them, and may not
    /// launder the provider's assertion into a kata measurement. A provider must
    /// therefore declare `true` here.
    /// `false` is a claim ABOUT KATA made by the provider, and
    /// [`admit`] refuses it by name.
    pub declares_construction_residue_unverified: bool,
    /// The kata measurement this provider's containment claim RESTS ON, echoed
    /// from the argv the supervisor handed it. `None` is decodable so that
    /// [`admit`] can refuse it by name ([`ProviderRefusal::MeasuredBasisAbsent`])
    /// rather than as a malformed frame.
    ///
    /// **This is the one field on this type that is not purely a claim, and it is
    /// not a measurement either: it is a provider's QUOTATION of one.** Its whole
    /// value comes from [`admit`] requiring it to be byte-equal to the basis kata
    /// measured in this process, so what it certifies is *"this provider is
    /// running under the mechanism kata measured"* and never *"this provider
    /// measured something"*.
    ///
    /// Required, never a `#[serde(default)]`, for [`AssignStage::plan`]'s
    /// reason one plane over: a defaulted field would let an older provider's
    /// certificate decode as `measured_basis = None`, which is exactly the
    /// silent downgrade the pair of numbers exists to prevent.
    #[serde(deserialize_with = "required_option")]
    pub measured_basis: Option<OciMeasuredBasis>,
}

/// What a provider claims to enforce — a CLOSED vocabulary, versioned by
/// [`CertificateVersion`].
///
/// One value. A provider that cannot say what it enforces has said nothing, and
/// any other spelling — `nothing_enforced`, `unknown` — is refused at decode as
/// an unknown variant, so no admission arm has to judge it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimedContainment {
    /// The provider asserts it constructs a sandbox of its own.
    ///
    /// **Admissible only beside a kata MEASUREMENT.** Without one the refusal's
    /// ground is that *"kata has measured nothing about a process it does not
    /// link"*, and the way to admit the claim is to ADD the measurement rather
    /// than to relax the rule. [`OciMeasuredBasis`] is that measurement:
    /// [`admit`] admits this claim if and only if the certificate carries a basis
    /// BYTE-EQUAL to the one kata measured on this host in this process, and
    /// refuses it by name otherwise. Where kata measured nothing, the
    /// unmeasured-claim refusal applies unchanged.
    ///
    /// `kata-provider-youki` is the provider that needs it: the containment
    /// around its stage is the pinned RUNTIME it `execve`s, which is precisely
    /// what `certify_youki` measures.
    ProviderEnforced,
}

impl ClaimedContainment {
    /// Stable snake_case token — the wire value, the log field and the refusal's
    /// quoted word, so all three cannot drift apart.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ClaimedContainment::ProviderEnforced => "provider_enforced",
        }
    }
}

/// The provider has taken the assignment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentAccepted {
    /// The id from [`AssignStage::assignment_id`], echoed.
    pub assignment_id: String,
}

/// The stage ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageCompleted {
    /// The id from [`AssignStage::assignment_id`], echoed.
    pub assignment_id: String,
    /// The stage's exit status, or `None` when it was killed by a signal or no
    /// exit status of its own reached the provider — each a different fact from
    /// exiting 0 that must not fold into one.
    ///
    /// # A SIGNAL DEATH IS NOT ALWAYS `None` on a container route, and that bounds
    /// what a reader may conclude
    ///
    /// Under an [`OciBundlePlan`] the process the provider waits on is the
    /// runtime CLIENT and not the stage, and `youki run` reports a container killed
    /// by a signal as its OWN exit code equal to that signal NUMBER (MEASURED: `9`
    /// for a `SIGKILL`ed init). So:
    ///
    /// * a CANCELLATION reports `None`, because the provider killed the container
    ///   itself and says so rather than forwarding the client's number;
    /// * a runtime client that FAILED without finishing its own delete — `youki
    ///   run` exits `255` for its own error, discarding the init's status if the
    ///   stage ran at all — reports `None`, because that number is the client's
    ///   and not the stage's; `None` there does not say the stage ran. The provider
    ///   tells the two apart by the container directory the client's own delete
    ///   removes (`kata-provider-youki`'s `client_exit` states the refused set and
    ///   the client errors it cannot see), so a stage that exited `255` by itself
    ///   still reports `Some(255)`;
    /// * any OTHER signal death — the kernel OOM killer being the one that matters
    ///   — arrives here as `Some(signal number)`, indistinguishable from a stage
    ///   that chose that exit code.
    ///
    /// **So an OOM verdict may never be read off this field.** The adversarial
    /// memory row scores `memory.events`' `oom_kill` counter in the stage's
    /// cgroup, which is the kernel's own answer; a row asserting `Some(137)` or
    /// `None` here would be asserting a coincidence.
    #[serde(deserialize_with = "required_option")]
    pub exit_code: Option<i32>,
    /// Bytes of stdout the stage produced, as the provider's spool file
    /// records them. A SIZE, not the payload — the bytes live under
    /// [`AssignStage::capture`]'s `spool_dir` and the supervisor reads them
    /// back itself, so a stage's output can never size a frame the peer
    /// must refuse.
    pub stdout_bytes: u64,
    /// Bytes of stderr the stage produced, likewise.
    pub stderr_bytes: u64,
    /// The two spool files together exceeded [`CaptureSpec::limit_bytes`]
    /// and the provider KILLED the stage for it — through the same path a
    /// wall-time budget or a cancel uses, never by letting the stage run on.
    /// A `capture_exceeded` completion can never be read as a complete
    /// capture: `stdout_bytes`/`stderr_bytes` are what was collected before
    /// the kill, not what the stage would have written.
    ///
    /// On the `interactive` OCI arm nothing is spooled — kata reads the
    /// FIFOs live — so a provider reports `0`, `0`, `false` here. It is the
    /// absence of capture reported as such, not a claim that the stage was
    /// silent.
    pub capture_exceeded: bool,
}

/// The provider refused the assignment; nothing ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssignmentRefused {
    /// The id from [`AssignStage::assignment_id`], echoed.
    pub assignment_id: String,
    /// The provider's own words.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// The handshake fold.
// ---------------------------------------------------------------------------

/// Why a supervisor refused a provider's handshake.
///
/// # These labels are NOT `kata_core::operational::ingress_fence::FrameRefusal`'s
///
/// That enum fences the WORKER/ATTEMPT protocol and its too-new arm is labelled
/// `protocol_too_new`. This one fences the PROVIDER protocol. They are two
/// different wires with two different version numbers, and an operator who read
/// one token as the other would upgrade the wrong component — briefing defect
/// class (d) at the exact place it costs an outage. Every label here is prefixed
/// `provider_`, and `the_provider_refusal_labels_cannot_be_confused_with_the_attempt_fences`
/// (`crates/worker/tests/provider_supervisor.rs`) is the pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderRefusal {
    /// The peer speaks a protocol BELOW this build's floor. Recourse: upgrade
    /// the PROVIDER.
    ProtocolTooOld {
        /// What the peer announced.
        claimed: ProtocolVersion,
        /// [`MIN_SUPPORTED_PROTOCOL_VERSION`].
        minimum: ProtocolVersion,
    },
    /// The peer speaks a protocol ABOVE this build's ceiling. Recourse: upgrade
    /// KATA. The opposite instruction from [`Self::ProtocolTooOld`], which is
    /// why they are two arms and not one.
    ProtocolTooNew {
        /// What the peer announced.
        claimed: ProtocolVersion,
        /// [`MAX_SUPPORTED_PROTOCOL_VERSION`].
        supported: ProtocolVersion,
    },
    /// The peer's certificate vocabulary is not this build's. Independent of the
    /// protocol arms above: this is the second number disagreeing on its own.
    CertificateVersionMismatch {
        /// What the peer announced.
        claimed: CertificateVersion,
        /// [`SUPPORTED_CERTIFICATE_VERSION`].
        supported: CertificateVersion,
    },
    /// The peer claims to enforce containment kata has not measured.
    ClaimedContainmentIsUnmeasured {
        /// The claim, as its own stable token.
        claimed: ClaimedContainment,
    },
    /// The peer declares that kata verified its construction residue. It did
    /// not, and cannot.
    ResidueVerificationClaimed,
    /// The peer claims to enforce containment and announces NO basis, on a host
    /// where kata DID measure one.
    ///
    /// Distinct from [`Self::ClaimedContainmentIsUnmeasured`], which is the case
    /// where KATA measured nothing: there the claim is unmeasurable, here it is
    /// merely unstated. The recourses are opposite — certify the host, versus fix
    /// the provider — which is why they are two arms.
    MeasuredBasisAbsent,
    /// The peer's basis is not the one kata measured.
    MeasuredBasisDisagrees {
        /// What KATA measured on this host, in this process.
        measured: Box<OciMeasuredBasis>,
        /// What the peer's certificate announced.
        announced: Box<OciMeasuredBasis>,
    },
    /// The peer announces a different name from the one the operator declared.
    ProviderIdentityMismatch {
        /// What the operator declared.
        declared: String,
        /// What the binary announced.
        announced: String,
    },
}

impl ProviderRefusal {
    /// Stable snake_case label — the metric dimension and the log field.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            ProviderRefusal::ProtocolTooOld { .. } => "provider_protocol_too_old",
            ProviderRefusal::ProtocolTooNew { .. } => "provider_protocol_too_new",
            ProviderRefusal::CertificateVersionMismatch { .. } => {
                "provider_certificate_version_mismatch"
            }
            ProviderRefusal::ClaimedContainmentIsUnmeasured { .. } => {
                "provider_claimed_containment_is_unmeasured"
            }
            ProviderRefusal::ResidueVerificationClaimed => "provider_residue_verification_claimed",
            ProviderRefusal::MeasuredBasisAbsent => "provider_measured_basis_absent",
            ProviderRefusal::MeasuredBasisDisagrees { .. } => "provider_measured_basis_disagrees",
            ProviderRefusal::ProviderIdentityMismatch { .. } => "provider_identity_mismatch",
        }
    }
}

impl std::fmt::Display for ProviderRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderRefusal::ProtocolTooOld { claimed, minimum } => write!(
                f,
                "the external provider announced protocol version {c} and this build's floor is \
                 {m}. Upgrade the PROVIDER: re-provision it from this build with `kata host \
                 setup`, or with `kata sandbox install-external-provider --name youki <dir>` \
                 and re-export `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` as the address it \
                 prints.",
                c = claimed.0,
                m = minimum.0,
            ),
            ProviderRefusal::ProtocolTooNew { claimed, supported } => write!(
                f,
                "the external provider announced protocol version {c} and this build implements \
                 up to {s}, so kata does not know what its frames mean. Upgrade KATA — \
                 downgrading the provider is the other refusal.",
                c = claimed.0,
                s = supported.0,
            ),
            ProviderRefusal::CertificateVersionMismatch { claimed, supported } => write!(
                f,
                "the external provider announced certificate version {c} and this build reads \
                 version {s}. The certificate number is INDEPENDENT of the protocol number: \
                 the frames may be mutually intelligible while the claims are not, and a \
                 certificate kata half-understands is one it must not read at all.",
                c = claimed.0,
                s = supported.0,
            ),
            ProviderRefusal::ClaimedContainmentIsUnmeasured { claimed } => write!(
                f,
                "the external provider's certificate claims `containment = {claim}`, and kata has \
                 measured NOTHING about a process it does not link. Admitting that claim would \
                 hand the provider a containment verdict nobody established. A provider is \
                 admitted only by quoting the rootless-OCI basis kata measured on this host, so \
                 the recourse is to certify the host, never to relax this.",
                claim = claimed.label(),
            ),
            ProviderRefusal::ResidueVerificationClaimed => f.write_str(
                "the external provider's certificate declares that kata VERIFIED its \
                 construction-residue syscalls. Kata did not and structurally cannot: those 13 \
                 syscalls are covered only by the provider's own inner filter, and a certificate \
                 must say so on its own face. Set `declares_construction_residue_unverified` to \
                 true.",
            ),
            ProviderRefusal::MeasuredBasisAbsent => f.write_str(
                "the external provider's certificate claims `containment = provider_enforced` and \
                 carries NO measured basis, on a host where kata measured one. The claim is \
                 admissible only as a QUOTATION of kata's own measurement (it is admitted by \
                 ADDING the measurement), and a certificate that claims enforcement \
                 without saying what it rests on has left the one comparison unmakeable. Have the \
                 provider echo the basis kata handed it on its argv.",
            ),
            ProviderRefusal::MeasuredBasisDisagrees {
                measured,
                announced,
            } => write!(
                f,
                "the external provider's certificate announces a measured basis that is NOT the \
                 one kata measured on this host: {fields:?} differ. A basis is admissible only \
                 byte-for-byte — a provider quoting a basis kata did not produce is asserting a \
                 containment property about some other host, some other runtime, or some other \
                 run, and admitting the nearest match is how a verdict gets attributed to a \
                 mechanism nobody measured. kata measured youki {mp} ({ms}) probe {mid}; the \
                 provider announced youki {ap} ({as_}) probe {aid}.",
                fields = measured.differing_fields(announced),
                mp = measured.youki.store_path,
                ms = measured.youki.sha256,
                mid = measured.functional_probe_id,
                ap = announced.youki.store_path,
                as_ = announced.youki.sha256,
                aid = announced.functional_probe_id,
            ),
            ProviderRefusal::ProviderIdentityMismatch {
                declared,
                announced,
            } => write!(
                f,
                "this node declared the external provider `{declared}` and the binary that \
                 answered announces itself as `{announced}`. Refusing rather than running the \
                 one that answered: a binary standing in for the provider an operator named is \
                 the substitution kata refuses everywhere else it can observe one."
            ),
        }
    }
}

/// A provider whose handshake was ADMITTED — constructible only by [`admit`].
///
/// Holds the certificate it was admitted on, so a consumer quotes the value that
/// passed rather than re-reading a `ProviderHello` that might have been mutated
/// since. It says nothing about containment: what kata knows about this process
/// is the floor kata installed on it, and that fact lives on the supervisor's
/// own measurement, not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedProvider {
    certificate: ProviderCertificate,
    protocol_version: ProtocolVersion,
    certificate_version: CertificateVersion,
}

impl AdmittedProvider {
    /// The certificate this provider was admitted on. A CLAIM.
    #[must_use]
    pub fn certificate(&self) -> &ProviderCertificate {
        &self.certificate
    }

    /// The protocol number the peer announced and this build accepted.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// The certificate number the peer announced and this build accepted.
    #[must_use]
    pub const fn certificate_version(&self) -> CertificateVersion {
        self.certificate_version
    }
}

/// The two numbers, judged: the protocol inside the supported range and the
/// certificate EQUAL to [`SUPPORTED_CERTIFICATE_VERSION`].
///
/// One function so [`admit`] and [`decode_opening_frame`] cannot disagree about
/// which peers they refuse on their numbers.
///
/// # Errors
/// [`ProviderRefusal::ProtocolTooOld`], [`ProviderRefusal::ProtocolTooNew`],
/// [`ProviderRefusal::CertificateVersionMismatch`].
fn judge_versions(
    protocol_version: ProtocolVersion,
    certificate_version: CertificateVersion,
) -> Result<(), ProviderRefusal> {
    if protocol_version < MIN_SUPPORTED_PROTOCOL_VERSION {
        return Err(ProviderRefusal::ProtocolTooOld {
            claimed: protocol_version,
            minimum: MIN_SUPPORTED_PROTOCOL_VERSION,
        });
    }
    if protocol_version > MAX_SUPPORTED_PROTOCOL_VERSION {
        return Err(ProviderRefusal::ProtocolTooNew {
            claimed: protocol_version,
            supported: MAX_SUPPORTED_PROTOCOL_VERSION,
        });
    }
    if certificate_version != SUPPORTED_CERTIFICATE_VERSION {
        return Err(ProviderRefusal::CertificateVersionMismatch {
            claimed: certificate_version,
            supported: SUPPORTED_CERTIFICATE_VERSION,
        });
    }
    Ok(())
}

/// **PURE** — admit or refuse a provider's opening frame.
///
/// Pure over its two inputs so every arm, including the ones no shipped provider
/// can produce, is reachable in a unit test on any host — the same pure/impure
/// split `kata_worker::sandbox_posture`'s folds use.
///
/// # The order of the checks is load-bearing
///
/// The PROTOCOL number is checked first because it bounds whether kata can read
/// the rest of the frame's meaning at all: a certificate decoded under a
/// protocol this build does not implement is a field kata guessed the semantics
/// of. Then the certificate NUMBER, then the certificate's CONTENT, then
/// identity — narrowing from "can I parse this" to "is it who I asked for".
///
/// # `measured` is KATA's own fact, and the ONLY thing that can admit an
/// enforcement claim
///
/// It is `Some` exactly when this process has certified the rootless-OCI
/// mechanism (`kata_worker::oci_runtime::certify_youki`, mapped by
/// `kata_worker::provider_supervisor::measured_basis_from_certification`), and
/// `None` otherwise. A certificate claiming
/// [`ClaimedContainment::ProviderEnforced`] is admitted if and only if it carries
/// a basis BYTE-EQUAL to this one; with `None` here the unmeasured-claim refusal
/// applies verbatim, because a claim kata has nothing to compare against is exactly the
/// claim that refusal describes.
///
/// # Errors
/// Every [`ProviderRefusal`] arm. There is no fallback: a refused handshake
/// leaves the provider unrun, which is the fail-closed direction — running a
/// stage on a provider kata could not understand is the silent downgrade this
/// protocol exists to refuse.
pub fn admit(
    hello: &ProviderHello,
    declared_name: &str,
    measured: Option<&OciMeasuredBasis>,
) -> Result<AdmittedProvider, ProviderRefusal> {
    // EXHAUSTIVE DESTRUCTURE. A field added to `ProviderHello`
    // is `E0027` here rather than a value silently ignored by the one function
    // whose job is to decide whether the peer is acceptable.
    let ProviderHello {
        protocol_version,
        certificate_version,
        certificate,
    } = hello;

    judge_versions(*protocol_version, *certificate_version)?;

    let ProviderCertificate {
        provider,
        containment,
        declares_construction_residue_unverified,
        measured_basis,
    } = certificate;

    // The CLAIM and the BASIS are one decision and are taken as one match, so
    // there is no order in which a claim could be accepted before its basis was
    // looked at. Every arm below is a refusal with a name; a basis byte-equal to
    // kata's is the only way past it.
    match (*containment, measured_basis.as_ref(), measured) {
        // Claims enforcement where KATA MEASURED NOTHING. The unmeasured-claim
        // refusal, unchanged: nothing about this changes when a basis the
        // provider invented is present, which is why the arm ignores it.
        (ClaimedContainment::ProviderEnforced, _, None) => {
            return Err(ProviderRefusal::ClaimedContainmentIsUnmeasured {
                claimed: *containment,
            });
        }
        // Kata measured one; the certificate does not say which.
        (ClaimedContainment::ProviderEnforced, None, Some(_)) => {
            return Err(ProviderRefusal::MeasuredBasisAbsent);
        }
        // Both present. BYTE-EQUAL or refused; there is no nearest match.
        (ClaimedContainment::ProviderEnforced, Some(announced), Some(measured)) => {
            if announced != measured {
                return Err(ProviderRefusal::MeasuredBasisDisagrees {
                    measured: Box::new(measured.clone()),
                    announced: Box::new(announced.clone()),
                });
            }
        }
    }
    if !*declares_construction_residue_unverified {
        return Err(ProviderRefusal::ResidueVerificationClaimed);
    }
    if provider != declared_name {
        return Err(ProviderRefusal::ProviderIdentityMismatch {
            declared: declared_name.to_owned(),
            announced: provider.clone(),
        });
    }

    Ok(AdmittedProvider {
        certificate: certificate.clone(),
        protocol_version: *protocol_version,
        certificate_version: *certificate_version,
    })
}

/// The certificate a provider announces when kata handed it a MEASURED BASIS on
/// its argv.
///
/// The shipped certificate and the shipped admission rule must not be able to
/// drift into disagreement without one file changing. This is the only
/// constructor in the tree that pairs [`ClaimedContainment::ProviderEnforced`]
/// with a basis, so *what an admissible certificate looks like* has one
/// spelling.
#[must_use]
pub fn measured_certificate(
    provider: impl Into<String>,
    basis: OciMeasuredBasis,
) -> ProviderCertificate {
    ProviderCertificate {
        provider: provider.into(),
        containment: ClaimedContainment::ProviderEnforced,
        // The residue declaration is untouched by the basis: kata still verifies
        // nothing about THIS process's construction residue, and the basis is
        // about kata's own runtime rather than about the provider. A provider
        // that read the basis as permission to flip this would be laundering its
        // own assertion, which is the thing `admit` refuses.
        declares_construction_residue_unverified: true,
        measured_basis: Some(basis),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name every admission fixture below declares, so a mismatch is always
    /// deliberate.
    const DECLARED: &str = "youki";

    /// A syntactically complete basis. Literal, because this crate is an absolute
    /// leaf: it cannot call `certify_youki`, and the property under test is the
    /// WIRE plus [`admit`]'s fold, both of which are pure over this value.
    fn basis() -> OciMeasuredBasis {
        OciMeasuredBasis {
            youki: PinnedRuntime {
                store_path: "/nix/store/0000000000000000000000000000000-youki/bin/youki".to_owned(),
                sha256: "a".repeat(64),
            },
            youki_version: "0.7.0".to_owned(),
            libseccomp_version: "2.6.1".to_owned(),
            apparmor_profile_name: "youki".to_owned(),
            apparmor_profile_sha256: "b".repeat(64),
            userns_restriction: MeasuredUsernsRestriction::Restricted,
            delegated_cgroup_parent: Some("/sys/fs/cgroup/user.slice".to_owned()),
            functional_probe_id: "kata-oci-certify-4242".to_owned(),
            residue_denied: true,
        }
    }

    fn hello_with(certificate: ProviderCertificate) -> ProviderHello {
        ProviderHello {
            protocol_version: PROTOCOL_VERSION,
            certificate_version: CERTIFICATE_VERSION,
            certificate,
        }
    }

    /// **NON-VACUITY, the admissible certificate.** Every refusal test below is
    /// satisfiable by a fold that refuses everything, so the `Ok` path is asserted
    /// first: the enforcement claim that quotes kata's own measurement.
    ///
    /// **Would red if:** `admit` grew a condition no shipped provider can satisfy
    /// — including a basis comparison that is not really equality, which would
    /// make this arm unreachable and every disagreement arm pass for the wrong
    /// reason.
    #[test]
    fn the_measured_certificate_is_admitted() {
        let enforced = admit(
            &hello_with(measured_certificate(DECLARED, basis())),
            DECLARED,
            Some(&basis()),
        )
        .expect("an enforcement claim quoting kata's own measurement");
        assert_eq!(
            enforced.certificate().containment,
            ClaimedContainment::ProviderEnforced,
            "the measured basis's point is that THIS claim is reachable"
        );
        assert_eq!(
            enforced.certificate().measured_basis.as_ref(),
            Some(&basis()),
            "the admitted certificate carries the basis it was admitted on, so a consumer quotes \
             the value that passed"
        );
        assert_eq!(
            enforced.certificate_version(),
            SUPPORTED_CERTIFICATE_VERSION
        );
    }

    /// **An enforcement claim on a host where kata measured NOTHING is refused
    /// as unmeasured.**
    ///
    /// The basis the provider carries is IRRELEVANT on this arm, and both halves
    /// are asserted: a build that reached for the certificate's own copy when
    /// kata's was absent would admit a provider that had simply made one up.
    ///
    /// **Would red if:** `measured = None` fell through to the equality
    /// comparison against the certificate's own basis.
    #[test]
    fn an_enforcement_claim_without_a_kata_measurement_is_refused() {
        for (arm, certificate) in [
            ("no basis announced", {
                let mut certificate = measured_certificate(DECLARED, basis());
                certificate.measured_basis = None;
                certificate
            }),
            (
                "a basis it invented",
                measured_certificate(DECLARED, basis()),
            ),
        ] {
            let refusal = admit(&hello_with(certificate), DECLARED, None)
                .expect_err("kata measured nothing, so the claim is unmeasured");
            assert_eq!(
                refusal.label(),
                "provider_claimed_containment_is_unmeasured",
                "{arm}: the unmeasured-claim refusal is the right one where kata measured nothing"
            );
            assert!(
                refusal.to_string().contains("measured NOTHING"),
                "{arm}: {refusal}"
            );
        }
    }

    /// **Kata measured a basis and the certificate claims enforcement without
    /// naming one.**
    ///
    /// A separate arm from the one above because the RECOURSES are opposite —
    /// certify the host, versus fix the provider — and an operator who read one
    /// as the other would change the wrong component.
    ///
    /// **Would red if:** the absent basis were read as "matches by default", or
    /// folded into the unmeasured arm.
    #[test]
    fn an_enforcement_claim_that_names_no_basis_is_refused() {
        let mut certificate = measured_certificate(DECLARED, basis());
        certificate.measured_basis = None;
        let refusal = admit(&hello_with(certificate), DECLARED, Some(&basis()))
            .expect_err("a claim with nothing to compare is refused");
        assert_eq!(refusal.label(), "provider_measured_basis_absent");
        assert!(
            refusal.to_string().contains("carries NO measured basis"),
            "{refusal}"
        );
    }

    /// **A basis that is not kata's is refused, on EVERY field, one at a time.**
    ///
    /// The loop is what makes this a byte-equality claim rather than an
    /// approximate one: a fold comparing only the digest — the plausible shortcut
    /// — would admit nine of these ten mutations, and each one is a containment
    /// property attributed to a host, a profile or a run that is not this one.
    /// The refusal must also NAME the field, so an operator is not handed two
    /// structs to diff.
    ///
    /// **Would red if:** the comparison narrowed to any subset of the fields, or
    /// `differing_fields` stopped covering one.
    #[test]
    fn a_basis_that_is_not_katas_is_refused_field_by_field() {
        let measured = basis();
        type BasisMutation = (&'static str, Box<dyn Fn(&mut OciMeasuredBasis)>);
        let mutations: Vec<BasisMutation> = vec![
            (
                "youki.store_path",
                Box::new(|b: &mut OciMeasuredBasis| {
                    b.youki.store_path = "/usr/bin/youki".to_owned();
                }),
            ),
            (
                "youki.sha256",
                Box::new(|b: &mut OciMeasuredBasis| b.youki.sha256 = "c".repeat(64)),
            ),
            (
                "youki_version",
                Box::new(|b: &mut OciMeasuredBasis| b.youki_version = "0.6.0".to_owned()),
            ),
            (
                // A provider echoing a basis measured on a host whose runtime
                // links a DIFFERENT libseccomp — or, as an empty string, none at
                // all. Admitting either would admit a stage fence written against
                // a runtime other than the one kata certified, and the empty case
                // is a fence that is written and never read.
                "libseccomp_version",
                Box::new(|b: &mut OciMeasuredBasis| b.libseccomp_version = "2.5.0".to_owned()),
            ),
            (
                "apparmor_profile_name",
                Box::new(|b: &mut OciMeasuredBasis| {
                    b.apparmor_profile_name = "youki-relaxed".to_owned();
                }),
            ),
            (
                "apparmor_profile_sha256",
                Box::new(|b: &mut OciMeasuredBasis| b.apparmor_profile_sha256 = "d".repeat(64)),
            ),
            (
                "userns_restriction",
                Box::new(|b: &mut OciMeasuredBasis| {
                    b.userns_restriction = MeasuredUsernsRestriction::Unrestricted;
                }),
            ),
            (
                "delegated_cgroup_parent",
                Box::new(|b: &mut OciMeasuredBasis| b.delegated_cgroup_parent = None),
            ),
            (
                "functional_probe_id",
                Box::new(|b: &mut OciMeasuredBasis| {
                    b.functional_probe_id = "kata-oci-certify-1".to_owned();
                }),
            ),
            (
                "residue_denied",
                Box::new(|b: &mut OciMeasuredBasis| b.residue_denied = false),
            ),
        ];
        assert_eq!(
            mutations.len(),
            measured
                .differing_fields(&OciMeasuredBasis {
                    youki: PinnedRuntime {
                        store_path: String::new(),
                        sha256: String::new(),
                    },
                    youki_version: String::new(),
                    libseccomp_version: String::new(),
                    apparmor_profile_name: String::new(),
                    apparmor_profile_sha256: String::new(),
                    userns_restriction: MeasuredUsernsRestriction::Unknown,
                    delegated_cgroup_parent: None,
                    functional_probe_id: String::new(),
                    residue_denied: false,
                })
                .len(),
            "this test must mutate EVERY comparable axis of the basis. A field added to \
             `differing_fields` without a mutation here would be compared by `PartialEq` and \
             never falsified"
        );

        for (field, mutate) in mutations {
            let mut announced = basis();
            mutate(&mut announced);
            assert_ne!(
                announced, measured,
                "{field}: the mutation must actually change the basis, else the arm is vacuous"
            );
            let refusal = admit(
                &hello_with(measured_certificate(DECLARED, announced)),
                DECLARED,
                Some(&measured),
            )
            .expect_err("a basis that is not kata's is refused");
            assert_eq!(
                refusal.label(),
                "provider_measured_basis_disagrees",
                "{field}: a basis differing in one field is a disagreement"
            );
            let text = refusal.to_string();
            assert!(
                text.contains(field),
                "{field}: the refusal must NAME the axis that differs, not print two structs: \
                 {text}"
            );
        }
    }

    /// A hello claiming `containment = nothing_enforced` is refused at the
    /// handshake. `provider_enforced`, echoing kata's measured basis, is the only
    /// claim in the vocabulary: the decoder refuses any other spelling as an
    /// unknown variant, so no fold arm is left to get it wrong.
    ///
    /// **Would red if:** the vocabulary regained a claim a provider could make
    /// without kata's measured basis, which `admit` would then have to judge.
    #[test]
    fn a_hello_claiming_nothing_enforced_is_refused_at_the_handshake() {
        let body = serde_json::to_vec(&serde_json::json!({
            "kind": "hello",
            "frame": {
                "protocol_version": PROTOCOL_VERSION,
                "certificate_version": CERTIFICATE_VERSION,
                "certificate": {
                    "provider": DECLARED,
                    "containment": "nothing_enforced",
                    "declares_construction_residue_unverified": true,
                    "measured_basis": null,
                },
            },
        }))
        .expect("json");
        let refusal = match decode_opening_frame(&body) {
            Err(error) => format!("{error:?}"),
            Ok(ProviderFrame::Hello(hello)) => match admit(&hello, DECLARED, Some(&basis())) {
                Err(refusal) => refusal.label().to_owned(),
                Ok(admitted) => {
                    panic!("a provider announcing `nothing_enforced` was admitted: {admitted:?}")
                }
            },
            Ok(other) => panic!("not a hello: {other:?}"),
        };
        assert!(
            refusal.contains("unknown variant `nothing_enforced`"),
            "refused, but not by the decoder: {refusal}"
        );
    }

    /// **Every certificate number but [`SUPPORTED_CERTIFICATE_VERSION`] is REFUSED,
    /// and it is the certificate number that refuses it — the protocol number
    /// stays this build's own.**
    ///
    /// A peer whose certificate vocabulary differs is refused with
    /// `provider_certificate_version_mismatch`, carrying both numbers, and never
    /// with a protocol arm.
    ///
    /// **Would red if:** the two constants were folded into one, or the
    /// certificate number were range-checked instead of compared for equality.
    #[test]
    fn a_certificate_number_other_than_the_supported_one_is_refused_by_that_number() {
        let supported = SUPPORTED_CERTIFICATE_VERSION.0;
        for claimed in [0, supported - 1, supported + 1, u16::MAX] {
            let mut hello = hello_with(measured_certificate(DECLARED, basis()));
            hello.certificate_version = CertificateVersion(claimed);
            let refusal = admit(&hello, DECLARED, None)
                .expect_err("another certificate vocabulary is not this build's");
            assert_eq!(refusal.label(), "provider_certificate_version_mismatch");
            assert!(
                matches!(
                    refusal,
                    ProviderRefusal::CertificateVersionMismatch {
                        claimed: CertificateVersion(c),
                        supported: s,
                    } if c == claimed && s == SUPPORTED_CERTIFICATE_VERSION
                ),
                "the refusal carries both numbers: {refusal:?}"
            );
            assert_eq!(
                hello.protocol_version, MAX_SUPPORTED_PROTOCOL_VERSION,
                "the protocol number is this build's own, so only the certificate arm can fire"
            );
        }
    }

    /// **A hello from another certificate vocabulary is refused BY NAME, not as a
    /// malformed frame.** Its measured basis carries an axis this build's
    /// `deny_unknown_fields` basis cannot decode, so a decoder that read the whole
    /// body first would report a vocabulary mismatch as a garbled peer. The
    /// opening frame's NUMBERS are judged before its body.
    ///
    /// **Would red if:** [`decode_opening_frame`] decoded the whole frame before
    /// reading `certificate_version`, or judged the numbers with anything but the
    /// refusal [`admit`] gives.
    #[test]
    fn a_hello_from_another_certificate_vocabulary_is_refused_by_name_before_its_body() {
        let hello = ProviderHello {
            protocol_version: PROTOCOL_VERSION,
            certificate_version: CertificateVersion(SUPPORTED_CERTIFICATE_VERSION.0 + 1),
            certificate: ProviderCertificate {
                containment: ClaimedContainment::ProviderEnforced,
                measured_basis: Some(basis()),
                ..measured_certificate(DECLARED, basis())
            },
        };
        let mut body: serde_json::Value =
            serde_json::to_value(ProviderFrame::Hello(hello)).expect("json");
        body["frame"]["certificate"]["measured_basis"]["an_axis_this_build_lacks"] =
            serde_json::Value::Null;
        let bytes = serde_json::to_vec(&body).expect("bytes");
        assert!(
            matches!(
                decode_frame::<ProviderFrame>(&bytes),
                Err(FrameError::Malformed(_))
            ),
            "NON-VACUITY: the other vocabulary's body must NOT decode as this build's frame"
        );

        match decode_opening_frame(&bytes) {
            Err(OpeningFrameError::Refused(refusal)) => assert_eq!(
                refusal.label(),
                "provider_certificate_version_mismatch",
                "{refusal}"
            ),
            other => panic!("another vocabulary's hello must be refused by name, got {other:?}"),
        }

        // The current vocabulary still decodes through the same door.
        let current = encode_frame(&ProviderFrame::Hello(hello_with(measured_certificate(
            DECLARED,
            basis(),
        ))))
        .expect("encode");
        assert!(
            matches!(
                decode_opening_frame(&current[FRAME_HEADER_BYTES..]),
                Ok(ProviderFrame::Hello(_))
            ),
            "a current hello decodes"
        );
    }

    /// **A certificate BODY without `measured_basis` does not decode at all**:
    /// the field is required and not a `#[serde(default)]`, so a peer's
    /// certificate from an older vocabulary is a decode refusal rather than a
    /// silent `None`.
    ///
    /// **Would red if:** the field gained `#[serde(default)]` — the one-character
    /// change that would let an older provider be read as *"announced no
    /// basis"* and admitted.
    #[test]
    fn a_certificate_without_the_basis_field_is_refused_rather_than_defaulted() {
        let mut doctored: serde_json::Value =
            serde_json::to_value(measured_certificate(DECLARED, basis())).expect("json");
        let object = doctored
            .as_object_mut()
            .expect("a certificate is an object");
        object.remove("measured_basis");
        let refusal = serde_json::from_value::<ProviderCertificate>(doctored)
            .expect_err("a missing field is a refusal, not a default");
        assert!(
            refusal.to_string().contains("measured_basis"),
            "the refusal must name the missing field: {refusal}"
        );
    }

    /// **An ABSENT optional key is refused, and a `null` one is accepted.**
    ///
    /// Every `Option` on this wire means *"kata resolved none"* or *"the provider
    /// has none"* — a decision. Serde's own treatment of `Option` would accept an
    /// omitted key as that decision, which is a `#[serde(default)]` this protocol
    /// forbids, arriving without the attribute that names it. Asserted on
    /// [`OciBundlePlan::egress_hook`] because that is the field with teeth: read as
    /// `None`, an `Egress` capsule's hooks are dropped and both sides answer
    /// `completed`.
    ///
    /// **Would red if:** `required_option` were dropped from any of the five
    /// `Option` fields on this wire — the loop below covers all of them.
    #[test]
    fn a_present_null_and_an_absent_key_are_different_frames() {
        let plan = oci_plan();
        assert_eq!(plan.egress_hook, None, "the fixture is hookless");
        let encoded = serde_json::to_value(&plan).expect("json");
        assert_eq!(
            encoded["egress_hook"],
            serde_json::Value::Null,
            "a `None` is written as an explicit null, so the absent case below is not what an \
             honest peer produces"
        );
        assert_eq!(
            serde_json::from_value::<OciBundlePlan>(encoded.clone())
                .expect("a null egress hook decodes"),
            plan
        );

        // Every Option-bearing struct on the wire, one absent key at a time.
        let plans = [
            (
                "oci_plan.cgroup_parent",
                encoded.clone(),
                vec!["cgroup_parent", "egress_hook"],
            ),
            (
                "basis.delegated_cgroup_parent",
                serde_json::to_value(basis()).expect("json"),
                vec!["delegated_cgroup_parent"],
            ),
            (
                "certificate.measured_basis",
                serde_json::to_value(measured_certificate(DECLARED, basis())).expect("json"),
                vec!["measured_basis"],
            ),
            (
                "completed.exit_code",
                serde_json::to_value(StageCompleted {
                    assignment_id: "a-1".to_owned(),
                    exit_code: None,
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                    capture_exceeded: false,
                })
                .expect("json"),
                vec!["exit_code"],
            ),
        ];
        let mut covered = 0;
        for (what, encoded, keys) in plans {
            for key in keys {
                let mut doctored = encoded.clone();
                doctored
                    .as_object_mut()
                    .expect("an object")
                    .remove(key)
                    .unwrap_or_else(|| panic!("{what}: {key} is not on the wire at all"));
                let refusal = match what.split('.').next() {
                    Some("oci_plan") => serde_json::from_value::<OciBundlePlan>(doctored).err(),
                    Some("basis") => serde_json::from_value::<OciMeasuredBasis>(doctored).err(),
                    Some("certificate") => {
                        serde_json::from_value::<ProviderCertificate>(doctored).err()
                    }
                    Some("completed") => serde_json::from_value::<StageCompleted>(doctored).err(),
                    _ => unreachable!("every plan above names its decoder: {what}"),
                };
                let refusal = refusal.unwrap_or_else(|| {
                    panic!(
                        "{what}: an ABSENT `{key}` decoded as a value. Serde reads a missing \
                         `Option` as `None` unless told otherwise, which is the \
                         `#[serde(default)]` this protocol forbids arriving without the attribute \
                         that names it"
                    )
                });
                assert!(
                    refusal.to_string().contains(key),
                    "{what}: the refusal must name the missing key: {refusal}"
                );
                covered += 1;
            }
        }
        assert_eq!(
            covered, 5,
            "there are five `Option` fields on this wire and every one of them must be covered here"
        );
    }

    /// **The basis has NO field an OCI bundle plan, a program or a filter could
    /// ride in.**
    ///
    /// It is kata's measurement of its own runtime, not a channel: a field here
    /// able to carry a path the provider should use, or bytes it should load,
    /// would turn a certificate the provider ECHOES into one it could steer. The
    /// field set is therefore pinned, and a new one is a certificate change that
    /// must be read here.
    #[test]
    fn the_measured_basis_field_set_is_fixed() {
        let encoded = serde_json::to_value(basis()).expect("json");
        let object = encoded.as_object().expect("the basis is a JSON object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            // SORTED — `serde_json::Value` without `preserve_order` is a `BTreeMap`.
            vec![
                "apparmor_profile_name",
                "apparmor_profile_sha256",
                "delegated_cgroup_parent",
                "functional_probe_id",
                "libseccomp_version",
                "residue_denied",
                "userns_restriction",
                "youki",
                "youki_version",
            ],
            "the measured basis's field set is fixed by this test. Every field is something KATA \
             measured about its own runtime; a field naming work for the provider to do would make \
             this a supervisor frame wearing a certificate's name"
        );
        assert_eq!(
            object["userns_restriction"],
            serde_json::json!("restricted"),
            "the userns axis is a closed snake_case vocabulary on the wire, not a number a reader \
             would have to interpret"
        );
    }

    /// A syntactically valid OCI bundle plan. Literal, because this crate is an
    /// absolute leaf: it cannot construct a `Capsule` or call
    /// `kata_worker::oci_bundle::spec_for`, and the property under test here is
    /// the WIRE — what a third-party implementation reading the frame table would
    /// have to produce and accept.
    fn oci_plan() -> OciBundlePlan {
        OciBundlePlan {
            config_json: r#"{"ociVersion":"1.0.2"}"#.to_owned(),
            rootfs_mountpoints: vec!["/work".to_owned(), "/out".to_owned()],
            container_id: "kata-0123456789abcdef".to_owned(),
            youki: PinnedRuntime {
                store_path: "/nix/store/0000000000000000000000000000000-youki/bin/youki".to_owned(),
                sha256: "0".repeat(64),
            },
            cgroup_parent: Some(
                "/sys/fs/cgroup/kata.test/kata.provider.youki.1/kata.oci.kata-0123456789abcdef"
                    .to_owned(),
            ),
            state_root: "/var/lib/kata/attempts/fixture/oci".to_owned(),
            stdio: OciStdio::Captured,
            egress_hook: None,
        }
    }

    /// The same plan with LIVE stdio — the `interactive` arm's wire fixture.
    fn interactive_oci_plan() -> OciBundlePlan {
        OciBundlePlan {
            stdio: OciStdio::Interactive(InteractiveStdio {
                stdin_fifo: "/var/lib/kata/attempts/fixture/io/stdin".to_owned(),
                stdout_fifo: "/var/lib/kata/attempts/fixture/io/stdout".to_owned(),
                stderr_fifo: "/var/lib/kata/attempts/fixture/io/stderr".to_owned(),
            }),
            ..oci_plan()
        }
    }

    /// **The two stdio arms are DISJOINT on the wire, and an ABSENT field is a
    /// refusal rather than `captured`.**
    ///
    /// The second half is the whole reason the protocol number moved to 5: a
    /// provider that read a missing `stdio` as `captured` would point a live vendor
    /// process's stdin at `/dev/null`, answer `accepted`, and leave both sides
    /// waiting out the wall budget.
    ///
    /// COUNTERFACTUAL: put `#[serde(default)]` on `OciBundlePlan::stdio` and the
    /// third assertion reds.
    #[test]
    fn a_plan_without_stdio_is_refused_and_the_two_arms_do_not_encode_alike() {
        let captured = serde_json::to_string(&oci_plan()).expect("a plan serializes");
        let interactive =
            serde_json::to_string(&interactive_oci_plan()).expect("a plan serializes");
        assert_ne!(
            captured, interactive,
            "the two stdio arms must be distinguishable on the wire"
        );
        assert!(
            captured.contains(r#""captured""#),
            "the captured arm must be labelled on the wire; got {captured}"
        );
        assert!(
            interactive.contains(r#""interactive""#) && interactive.contains("stdin_fifo"),
            "the interactive arm must carry its three FIFO paths; got {interactive}"
        );

        let mut without: serde_json::Value =
            serde_json::from_str(&captured).expect("the plan round-trips through a value");
        assert!(
            without
                .as_object_mut()
                .expect("a plan encodes as an object")
                .remove("stdio")
                .is_some(),
            "the fixture must have carried a `stdio` to remove"
        );
        let refused: Result<OciBundlePlan, serde_json::Error> = serde_json::from_value(without);
        assert!(
            refused.is_err(),
            "a plan with NO `stdio` must be REFUSED, never read as `captured`: a provider that \
             defaulted it would point a live vendor process's stdin at /dev/null and answer \
             `accepted`"
        );
    }

    /// **The OCI plan is the only plan, and a peer's tagged plan is refused at
    /// decode.**
    ///
    /// The assignment carries the plan untagged, so a plan `kind` — `none`, asking
    /// for a bare program, or version 8's `oci` wrapper — is refused when the
    /// assignment is decoded, naming the key, before any provider code could
    /// choose to run it.
    ///
    /// **Would red if:** the plan regained a tagged enum with a `None` arm, or
    /// [`OciBundlePlan`] lost `deny_unknown_fields`.
    #[test]
    fn the_oci_plan_is_the_only_plan_on_the_wire() {
        let plan = oci_plan();
        let bytes = serde_json::to_vec(&plan).expect("a plan serializes");
        let decoded: OciBundlePlan =
            serde_json::from_slice(&bytes).expect("and round-trips unchanged");
        assert_eq!(
            decoded, plan,
            "a plan that does not survive its own encoding cannot be assigned"
        );

        let assign = serde_json::to_value(SupervisorFrame::Assign(assign("a-none")))
            .expect("an assignment serializes");
        for tagged in [
            serde_json::json!({ "kind": "none" }),
            serde_json::json!({ "kind": "oci", "plan": serde_json::to_value(&plan).expect("json") }),
        ] {
            let mut doctored = assign.clone();
            doctored["frame"]["plan"] = tagged.clone();
            let body = serde_json::to_vec(&doctored).expect("json");
            let mut wire = u32::try_from(body.len())
                .expect("small")
                .to_be_bytes()
                .to_vec();
            wire.extend_from_slice(&body);
            let decoded: Result<SupervisorFrame, FrameError> =
                read_frame(&mut std::io::Cursor::new(wire));
            let refusal =
                decoded.expect_err("an assignment carrying a tagged plan must be refused");
            assert!(
                refusal.to_string().contains("unknown field `kind`"),
                "the decode refusal must name the tag the peer sent ({tagged}): {refusal}"
            );
        }
    }

    /// **An unknown field on a plan is REFUSED, not ignored.**
    ///
    /// `deny_unknown_fields` is the rule [`AssignStage`]'s doc states for the
    /// whole protocol: a peer that sent a field this build does not know is
    /// speaking a version this build cannot honour, and accepting the rest would
    /// be applying a containment plan with a piece missing.
    #[test]
    fn an_unknown_field_on_the_oci_plan_is_refused() {
        let mut doctored: serde_json::Value = serde_json::to_value(oci_plan()).expect("json");
        doctored["landlock_ruleset"] = serde_json::json!("/whatever");
        let refusal = serde_json::from_value::<OciBundlePlan>(doctored)
            .expect_err("an unknown field must be refused");
        assert!(
            refusal.to_string().contains("landlock_ruleset"),
            "the refusal must name the field the peer added: {refusal}"
        );

        let mut doctored: serde_json::Value = serde_json::to_value(oci_plan().youki).expect("json");
        doctored["blake3"] = serde_json::json!("deadbeef");
        let refusal = serde_json::from_value::<PinnedRuntime>(doctored)
            .expect_err("an unknown field on the pinned runtime must be refused");
        assert!(refusal.to_string().contains("blake3"), "{refusal}");
    }

    /// **The OCI plan has NO field a seccomp program can ride in.**
    ///
    /// The kata seccomp floor must never ride the wire, and that is asserted
    /// over the plan's own serialized SHAPE rather than over a value: this plan
    /// must have no field a filter could ride in. A field added here later that carried
    /// filter bytes would fail this test before it could carry a floor.
    #[test]
    fn the_oci_plan_carries_no_filter_bytes_field() {
        let encoded = serde_json::to_value(oci_plan()).expect("json");
        let object = encoded.as_object().expect("the plan is a JSON object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            // SORTED, because `serde_json::Value` without `preserve_order` is a
            // `BTreeMap`. Declaration order is what the WIRE carries and what the
            // byte golden in `crates/worker/tests/fixtures/oci/` pins; this
            // assertion is about the field SET.
            vec![
                "cgroup_parent",
                "config_json",
                "container_id",
                "egress_hook",
                "rootfs_mountpoints",
                "state_root",
                "stdio",
                "youki",
            ],
            "the OCI plan's field set is fixed by this test. A new field is a protocol change and \
             must be read here — in particular, a field able to carry a compiled seccomp program \
             would put the kata floor on the wire, and the floor is the one thing a provider \
             must not be able to decline"
        );
        assert!(
            !object.contains_key("stage_seccomp_bpf") && !object.contains_key("kata_floor_bpf"),
            "the container's fence lives INSIDE config_json as the OCI spec's linux.seccomp; \
             there is no separate filter channel on this plan"
        );
    }

    /// **The capture surface is pinned on the wire: the assignment names a
    /// SPOOL, the completion names SIZES — and inline output text has no field
    /// to ride.**
    ///
    /// The captured bytes live in files the provider wrote, never in the frame,
    /// so an inline `stdout`/`stderr`/`truncated` field would put unbounded output
    /// on the wire. The assertion is over the serialized FIELD SETS, which is
    /// what a peer reads.
    ///
    /// **Would red if:** `StageCompleted` regrew an inline `stdout`/`stderr`
    /// field, or `AssignStage` lost `capture`.
    #[test]
    fn the_capture_surface_is_pinned_on_the_wire() {
        let assign = AssignStage {
            capture: CaptureSpec {
                spool_dir: "/attempts/a-6/capture".to_owned(),
                limit_bytes: 67_108_864,
            },
            ..assign("a-6")
        };
        let encoded = serde_json::to_value(&assign).expect("an assignment serializes");
        let fields = encoded
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            fields,
            vec!["assignment_id", "capture", "plan", "protocol_version"],
            "the assignment's field set: the plan, the spool and the two identifiers, and no \
             command of its own"
        );
        assert_eq!(
            encoded["capture"]["spool_dir"], "/attempts/a-6/capture",
            "the spec travels"
        );
        assert_eq!(
            encoded["capture"]["limit_bytes"],
            serde_json::json!(67_108_864),
            "and so does the COMBINED bound"
        );

        let completed = StageCompleted {
            assignment_id: "a-6".to_owned(),
            exit_code: Some(0),
            stdout_bytes: 42,
            stderr_bytes: 7,
            capture_exceeded: false,
        };
        let encoded = serde_json::to_value(&completed).expect("a completion serializes");
        let fields = encoded
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(
            fields,
            vec![
                "assignment_id",
                "capture_exceeded",
                "exit_code",
                "stderr_bytes",
                "stdout_bytes",
            ],
            "the completion reports SIZES and the kill flag — no `stdout`, `stderr` or \
             `truncated`, and adding one must fail here rather than slide past"
        );
        for removed in ["stdout", "stderr", "truncated"] {
            assert!(
                !encoded
                    .as_object()
                    .expect("an object")
                    .contains_key(removed),
                "{removed} has no field to ride"
            );
        }

        // And the same shape survives the length-delimited codec.
        let frame = ProviderFrame::Completed(completed.clone());
        let bytes = encode_frame(&frame).expect("the frame encodes");
        let body = &bytes[FRAME_HEADER_BYTES..];
        let on_the_wire: serde_json::Value =
            serde_json::from_slice(body).expect("the body is JSON");
        assert_eq!(
            on_the_wire["frame"]["stdout_bytes"],
            serde_json::json!(42),
            "the length-delimited frame carries the same shape"
        );
    }

    /// A complete assignment, as this build's supervisor writes one.
    fn assign(id: &str) -> AssignStage {
        AssignStage {
            protocol_version: PROTOCOL_VERSION,
            assignment_id: id.to_owned(),
            plan: oci_plan(),
            capture: CaptureSpec {
                spool_dir: format!("/attempts/{id}/capture"),
                limit_bytes: 1_048_576,
            },
        }
    }

    /// **A version-8 provider is refused by its NUMBER at the handshake.**
    ///
    /// Version 9 removed the assignment's `program`, `args`, `env` and `cwd`, so a
    /// version-8 provider would refuse every version-9 assignment as malformed.
    /// The disagreement is caught one frame earlier, at the hello, where it has a
    /// name and an operator recourse.
    ///
    /// **Would red if:** the floor stayed at 8 after the frame shape moved.
    #[test]
    fn a_version_8_provider_is_refused_by_its_number_at_the_handshake() {
        let mut hello = hello_with(measured_certificate(DECLARED, basis()));
        hello.protocol_version = ProtocolVersion(8);
        let body = serde_json::to_vec(&ProviderFrame::Hello(hello)).expect("json");
        match decode_opening_frame(&body) {
            Err(OpeningFrameError::Refused(refusal)) => {
                assert_eq!(refusal.label(), "provider_protocol_too_old", "{refusal}");
            }
            other => panic!("a version-8 hello must be refused by its number, got {other:?}"),
        }
    }

    /// **An assignment carrying a version-8 command field is refused at decode.**
    ///
    /// Under the one OCI plan the stage's argv, environment and working directory
    /// are inside `config_json` and the program is the plan's pinned runtime, so
    /// the frame has no field for any of them. A peer that sends one is refused by
    /// the generic `deny_unknown_fields` decode, before any provider code runs.
    ///
    /// **Would red if:** [`AssignStage`] regained any of the four fields, or lost
    /// `deny_unknown_fields`.
    #[test]
    fn an_assignment_carrying_a_version_8_command_field_is_refused_at_decode() {
        let current = serde_json::to_value(assign("a-8")).expect("json");
        for (key, value) in [
            ("program", serde_json::json!("/bin/sh")),
            ("args", serde_json::json!(["-c", "true"])),
            ("env", serde_json::json!({ "PATH": "/bin" })),
            ("cwd", serde_json::json!("/work")),
        ] {
            let mut doctored = current.clone();
            doctored[key] = value;
            let refusal = serde_json::from_value::<AssignStage>(doctored)
                .err()
                .unwrap_or_else(|| panic!("an assignment carrying `{key}` decoded"));
            assert!(
                refusal
                    .to_string()
                    .contains(&format!("unknown field `{key}`")),
                "the decode refusal must name `{key}`: {refusal}"
            );
        }
    }

    /// **A protocol number outside `[MIN, MAX]` is refused at the handshake, by
    /// NAME, before any frame** — below the floor as `provider_protocol_too_old`
    /// (upgrade the provider), above the ceiling as `provider_protocol_too_new`
    /// (upgrade kata). Each refusal names the number it was handed and the bound
    /// it was measured against.
    ///
    /// **Would red if:** either bound were dropped, or the two arms were folded
    /// into one — they carry opposite recourses.
    #[test]
    fn a_protocol_number_outside_the_supported_range_is_refused_by_name() {
        let below = MIN_SUPPORTED_PROTOCOL_VERSION.0 - 1;
        let above = MAX_SUPPORTED_PROTOCOL_VERSION.0 + 1;
        for (claimed, label, bound) in [
            (
                0,
                "provider_protocol_too_old",
                MIN_SUPPORTED_PROTOCOL_VERSION.0,
            ),
            (
                below,
                "provider_protocol_too_old",
                MIN_SUPPORTED_PROTOCOL_VERSION.0,
            ),
            (
                above,
                "provider_protocol_too_new",
                MAX_SUPPORTED_PROTOCOL_VERSION.0,
            ),
            (
                u16::MAX,
                "provider_protocol_too_new",
                MAX_SUPPORTED_PROTOCOL_VERSION.0,
            ),
        ] {
            let mut hello = hello_with(measured_certificate(DECLARED, basis()));
            hello.protocol_version = ProtocolVersion(claimed);
            let refusal = admit(&hello, DECLARED, None).expect_err("outside the supported range");
            assert_eq!(
                refusal.label(),
                label,
                "the named refusal, not a generic decode error"
            );
            let text = refusal.to_string();
            assert!(
                text.contains(&format!("protocol version {claimed}")),
                "the refusal names the version it was handed: {text}"
            );
            assert!(
                text.contains(&bound.to_string()),
                "and the bound it was measured against: {text}"
            );
        }
    }
}
