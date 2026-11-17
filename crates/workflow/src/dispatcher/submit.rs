//! Submit path for [`Dispatcher`]: sandbox resolution, checked
//! dispatch submission, cached completions, and approval-gate submission.

use kata_types::sandbox::SecretRef;

use super::{
    BTreeMap, DispatchFrame, Dispatcher, KataError, KataResult, SandboxDirective, SandboxProfile,
    SandboxRef, Ulid, dispatcher_now_ms, read_secret, warn,
};

/// The three PER-DISPATCH facts one delivery stamps onto its outgoing frame.
///
/// One value rather than three returns, because they are read together from one
/// durable row at one instant and stamping a subset is the defect: a frame carrying
/// this dispatch's epoch and the previous dispatch's command id names a command the
/// fence will not match.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct PerDispatchStamps {
    lease_epoch: i64,
    command_id: Option<Ulid>,
    start_deadline_ms: Option<u64>,
}

impl Dispatcher {
    /// THE per-dispatch read.
    ///
    /// # Invariant
    ///
    /// ONE READ, ONE INSTANT. The dispatch stamps — generation and command — are read
    /// off the `attempts` row the placement writer just advanced, at delivery, so the
    /// frame carries the row's own answer to "which generation is this?".
    ///
    /// An attempt with no durable row keeps epoch 0 and no command: the ingress fence
    /// lets an unknown attempt through rather than deleting the only report it will get.
    fn per_dispatch_stamps(&self, attempt_id: Ulid) -> KataResult<PerDispatchStamps> {
        let start_deadline_ms = self.assignment_start_deadline.and_then(|deadline| {
            let deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
            if deadline_ms == 0 {
                None
            } else {
                Some(dispatcher_now_ms().saturating_add(deadline_ms))
            }
        });
        let Some(placement) = self.attempt_durable_placement(attempt_id)? else {
            return Ok(PerDispatchStamps {
                lease_epoch: 0,
                command_id: None,
                start_deadline_ms,
            });
        };
        Ok(PerDispatchStamps {
            lease_epoch: placement.lease_epoch,
            command_id: self.attempt_dispatch_command_id(attempt_id, placement.lease_epoch)?,
            start_deadline_ms,
        })
    }

    /// The DELIVERY clone of one dispatch frame.
    ///
    /// The door over [`Self::per_dispatch_stamps`] and
    /// [`DispatchFrame::stamp_for_dispatch`].
    pub fn frame_for_dispatch(&self, frame: &DispatchFrame) -> KataResult<DispatchFrame> {
        let stamps = self.per_dispatch_stamps(frame.attempt_id())?;
        let mut frame = frame.clone();
        frame.stamp_for_dispatch(
            stamps.lease_epoch,
            stamps.command_id,
            stamps.start_deadline_ms,
        );
        Ok(frame)
    }

    /// Resolve a stage's [`SandboxRef`] into a concrete
    /// [`SandboxDirective`] using the workflow-local profile map.
    /// Callers (typically the runner) feed the returned directive
    /// into the capsule submission's sandbox facts.
    ///
    /// Returns `Ok(None)` when the stage declared no sandbox. A capsule binds
    /// its `/work` from the recorded head's content reference, so no host
    /// directory is materialized and no path is stamped into `env`.
    ///
    /// Error conditions:
    /// - `SandboxRef::Named(n)` where `n` is not in `profiles`:
    ///   `KataError::Validation` with a descriptive message.
    ///
    /// There is no system-level profile resolution: only the
    /// workflow-local map is read.
    ///
    /// Signature remains async for caller stability and future secret-provider
    /// resolution.
    /// # The caller's two INDEPENDENT verdicts
    ///
    /// `confine_to_declared_inputs` and `content_cacheable` are the caller's
    /// answers to two different questions, threaded here and stamped verbatim
    /// onto the matching [`SandboxDirective`] fields. Pass
    /// [`ExecutionProgramStage::should_confine_to_declared_inputs`] and
    /// [`ExecutionProgramStage::is_content_cacheable`] — both computed against
    /// the SAME `profiles` map this call resolves against.
    ///
    /// They are TWO parameters, not one `hermetic: bool`: a single parameter
    /// would mean content-cacheability at the call site and declared-input-only
    /// in the worker, which would make the contained-nondeterministic model
    /// editor unrepresentable; see [`SandboxDirective::confine_to_declared_inputs`].
    /// Threading the already-computed predicates — rather than recomputing
    /// net/fs here — keeps each boundary and its derivation the SAME set by
    /// construction.
    ///
    /// Both are folded into the capsule permissions hash; neither selects a wrap
    /// behaviour. Both are moot when `sandbox` is `None` (no directive is built).
    #[allow(clippy::unused_async, clippy::too_many_lines)]
    pub async fn resolve_sandbox(
        &self,
        sandbox: Option<&SandboxRef>,
        profiles: &BTreeMap<String, SandboxProfile>,
        assignment_id: Ulid,
        _execution_id: Ulid,
        confine_to_declared_inputs: bool,
        content_cacheable: bool,
    ) -> KataResult<Option<SandboxDirective>> {
        // A content-cache claim on a `HostUnconfined` stage is refused, and the
        // two-axis split makes that quadrant (`cacheable ∧ ¬confined`)
        // REPRESENTABLE. Representable and unrefused is how a defect gets in
        // later, by a caller that does not exist today. A stage stamped this way would run on
        // the ambient worker toolchain, host `$PATH`, `$HOME` and forwarded
        // operator env while claiming its result is a content-addressed function
        // of its declared inputs.
        //
        // Cheap to state, impossible to reach from today's stamping sites (every
        // one derives cacheability through `is_content_cache_eligible`, whose
        // `Contained` conjunct puts it on the diagonal). Stated anyway: the
        // implication is the split's soundness condition, so it belongs in code
        // rather than in the field's prose.
        if content_cacheable && !confine_to_declared_inputs {
            return Err(KataError::Internal(
                "dispatcher: a stage was stamped content_cacheable without \
                 confine_to_declared_inputs. A content-cache key asserts the result is a \
                 function of the DECLARED inputs, which is only true if the action was held \
                 to them; ADR-0001 refuses `HostUnconfined` with a content-cache claim. \
                 Cacheability implies confinement, never the converse."
                    .to_string(),
            ));
        }

        let Some(sandbox_ref) = sandbox else {
            return Ok(None);
        };

        let profile = match sandbox_ref {
            SandboxRef::Named(name) => profiles.get(name).ok_or_else(|| {
                KataError::Validation(format!(
                    "dispatcher: sandbox profile \"{name}\" is not defined in \
                     this workflow. Add `\"{name}\": sandbox_profile(...)` to \
                     `workflow(sandbox_profiles = {{...}})` or pass \
                     `sandbox_profile(...)` directly to `stage(sandbox = ...)`."
                ))
            })?,
            SandboxRef::Inline(profile) => profile.as_ref(),
        };

        let mut secret_tokens: BTreeMap<String, SecretRef> = BTreeMap::new();

        if !profile.secrets.is_empty() {
            // The capsule has no field a secret value can inhabit, so a declared
            // secret is resolved here only to prove its declaration readable; its
            // value is not delivered to the stage.
            warn!(
                %assignment_id,
                secrets = profile.secrets.len(),
                "dispatcher: profile secrets are checked readable but their values are not \
                 delivered to the stage; only their declarations enter the capsule's \
                 permissions hash"
            );
            for (secret_name, secret_ref) in &profile.secrets {
                // PROVE the declaration resolves, then DROP the value.
                //
                // The directive this builds is the AT-REST one — it is what all
                // four durable writers encode — so it must not hold the plaintext
                // (`SandboxDirective::secret_tokens` holds declarations only).
                // But the operator-facing failure for an unset env var or an
                // unreadable file belongs HERE, at resolution of the declared
                // profile, and not at the dispatch seam three steps downstream
                // where it would arrive after the pending row was written. So
                // the read happens now for its ERROR alone, and the
                // value is discarded: the directive carries only the declaration.
                // An env read and a small-file read are cheap; a credential in a
                // retained SQLite blob is not.
                drop(read_secret(secret_ref)?);
                secret_tokens.insert(secret_name.clone(), secret_ref.clone());
            }
        }

        let directive = SandboxDirective {
            exec: profile.exec.clone(),
            fs: profile.fs.clone(),
            net: profile.net.clone(),
            env: BTreeMap::new(),
            secret_tokens,
            // Propagate an optional image for image-backed providers.
            image: profile.image.clone(),
            // The caller's two verdicts, stamped verbatim onto the two
            // independent axes. `false`/`false` for every agent/`ModelCall`
            // stage (and any reaching-I/O deterministic stage).
            confine_to_declared_inputs,
            content_cacheable,
            read_closure: Vec::new(),
            write_closure: Vec::new(),
            determinism_pinned: false,
        };

        Ok(Some(directive))
    }
}
