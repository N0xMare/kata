//! Behavioral git overrides shared by production and fixtures.
//!
//! Identity and trunk are deliberately absent: the host supplies those facts.
//! Credentials/remotes are also inherited; these overrides only prevent hooks,
//! signing, global ignores, newline conversion, and detached auto-maintenance
//! from changing a VCS action. `gc.auto` / `maintenance.auto` are pinned off
//! because a kata `git` call must never launch a detached repack that rewrites
//! `objects/pack` under a reader that just opened the odb — measured: a
//! commit loop detached `maintenance run --auto`, whose repack left a
//! half-written `.tmp` pack that jj's `import_head` refused
//! (`Failed to read Git HEAD target commit`).
//!
//! `core.fsync` adds `loose-object` and `reference` to git's default hardening
//! (which syncs packs only), with `core.fsyncMethod=fsync`: a loose object or a
//! ref a kata `git` child writes is synced before it is renamed into place, so
//! a power loss never leaves one of them empty — a fetch into an execution's
//! target pins, a push's local tracking ref. The directory entry its rename
//! made is not synced by git; the caller's repository barrier
//! (`kata_vcs::jj` `durability`) is what makes the write durable before a
//! transition depends on it. An operator config that weakens either key is
//! overridden for kata's children only.
//!
//! No hook from any configuration runs inside a kata `git` child. Git runs a
//! hook from two places: the hooks directory, which `core.hooksPath=/dev/null`
//! empties, and `hook.<name>.command` entries in the system, global or
//! repository config, which `core.hooksPath` does not reach (measured on git
//! 2.56: a global and a repository-local one both ran under it). Git 2.56
//! has no switch for every configured hook at once; `hook.<event>.enabled=false`
//! turns off every hook for one event "regardless of any per-hook
//! `hook.<name>.enabled` settings" (git-config(1)), and a `-c` value outranks
//! every config file, so the set below names each event githooks(5) of git 2.56
//! lists. `core.fsmonitor=false` stops the fsmonitor hook command a config may
//! name, which is not run through either path. Refused exactly: those events'
//! hooks, from the hooks directory and from config, and the fsmonitor command.
//! Not refused: an event a later git adds (kata's tests read the host git's
//! githooks(5) and fail on one this list lacks), and a hook the REMOTE end of a
//! local-path push or fetch runs — receive-pack is not handed `-c` settings, so
//! a local remote's own hooks run as a forge's would.

pub const GIT_EXECUTION_OVERRIDES: &[(&str, &str)] = &[
    ("commit.gpgsign", "false"),
    ("tag.gpgsign", "false"),
    ("core.hooksPath", "/dev/null"),
    ("core.fsmonitor", "false"),
    ("hook.applypatch-msg.enabled", "false"),
    ("hook.pre-applypatch.enabled", "false"),
    ("hook.post-applypatch.enabled", "false"),
    ("hook.pre-commit.enabled", "false"),
    ("hook.pre-merge-commit.enabled", "false"),
    ("hook.prepare-commit-msg.enabled", "false"),
    ("hook.commit-msg.enabled", "false"),
    ("hook.post-commit.enabled", "false"),
    ("hook.pre-rebase.enabled", "false"),
    ("hook.post-checkout.enabled", "false"),
    ("hook.post-merge.enabled", "false"),
    ("hook.pre-push.enabled", "false"),
    ("hook.pre-receive.enabled", "false"),
    ("hook.update.enabled", "false"),
    ("hook.proc-receive.enabled", "false"),
    ("hook.post-receive.enabled", "false"),
    ("hook.post-update.enabled", "false"),
    ("hook.reference-transaction.enabled", "false"),
    ("hook.push-to-checkout.enabled", "false"),
    ("hook.pre-auto-gc.enabled", "false"),
    ("hook.post-rewrite.enabled", "false"),
    ("hook.sendemail-validate.enabled", "false"),
    ("hook.fsmonitor-watchman.enabled", "false"),
    ("hook.p4-changelist.enabled", "false"),
    ("hook.p4-prepare-changelist.enabled", "false"),
    ("hook.p4-post-changelist.enabled", "false"),
    ("hook.p4-pre-submit.enabled", "false"),
    ("hook.post-index-change.enabled", "false"),
    ("core.autocrlf", "false"),
    ("core.excludesFile", "/dev/null"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("core.fsync", "loose-object,reference"),
    ("core.fsyncMethod", "fsync"),
];
