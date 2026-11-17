# The rootless-OCI containment binary, built WITH the seccomp feature.
#
# WHY THIS FILE EXISTS. `nixpkgs#youki` builds the `youki` binary crate with
# `cargoBuildFlags = [ "-p" "youki" "--features" "systemd" ]`. That crate
# declares NO default features and takes `libcontainer` with
# `default-features = false`, so `libcontainer/libseccomp` — reached only
# through youki's own `seccomp` feature — is OFF. `libseccomp` is in
# `buildInputs`, but nothing links it. The consequence is not a build error:
# `libcontainer`'s init process gates every seccomp call behind
# `#[cfg(feature = "libseccomp")]`, and the `#[cfg(not(...))]` arm only
# `tracing::warn!`s. A `config.json` carrying `linux.seccomp` therefore runs
# with NO filter installed and NO refusal — measured as `Seccomp_filters: 0`
# inside a container started from kata's own golden bundle.
#
# So the pin comes from here instead: the same nixpkgs derivation, the same
# upstream release (0.7.0 is the newest youki release as of 2026-09-22), with
# `seccomp` added to `cargoBuildFlags`. `cargoHash` is unchanged because
# nixpkgs vendors the whole `Cargo.lock` regardless of which features are
# selected — the `libseccomp` crate was already vendored, merely not compiled.
#
# HOW TO REALIZE IT, from the kata checkout (the exact command
# `config/youki-pin.toml` quotes):
#
#     nix build -o .kata/youki-root -f nix/youki.nix
#     readlink .kata/youki-root          # the store path to re-pin
#
# `-o` and not `--no-link`: that symlink is an INDIRECT GC ROOT, and without one
# the pinned bytes are collected by the next `nix store gc` — a pin naming a
# collected path is `binary_absent` for a runtime nobody uninstalled. `.kata/` is
# already gitignored. `nix profile install -f nix/youki.nix` roots it in a
# profile instead, if an operator prefers that.
#
# The nixpkgs revision is pinned by hash: a channel bump must be an EDIT here,
# never a silent change to the bytes AppArmor is asked to cover.
#
# WHAT THIS FILE DOES NOT FIX. `youki features` still reports
# `linux.seccomp: null` on this build — 0.7.0's `commands/features.rs` carries
# a literal `// TODO: Expose seccomp support information` and hard-codes the
# section's absence, independent of `cfg!(feature = ...)`. The build-feature
# witness that DOES move is `youki info`'s `libseccomp: <version>` line, which
# is `#[cfg(feature = "seccomp")]`-gated and fed by `build.rs` from
# `pkg_config::probe_library("libseccomp")`. That is the line
# `kata_worker::oci_runtime::certify_youki` parses.
# `pkgs` is an argument so the flake passes ITS nixpkgs (the same pinned
# revision — flake.lock records it) instead of this file fetching a second
# copy. The default keeps `nix build -f nix/youki.nix` working, which
# `config/youki-pin.toml`'s `realised_by` and the AppArmor re-render flow
# still invoke.
{
  pkgs ? import (import ./nixpkgs-pin.nix) { system = builtins.currentSystem; },
}:

pkgs.youki.overrideAttrs (old: {
  pname = "youki-seccomp";
  # youki 0.7.0's lost-SIGCHLD race, closed at the source. `commands/run.rs`
  # calls `container.start()` and only THEN blocks the signals
  # `handle_foreground` `sigwait`s on; SIGCHLD's default disposition is IGNORE,
  # so an init that exits in that window has its SIGCHLD DISCARDED by the kernel
  # (`kernel/signal.c`, `prepare_signal`) rather than left pending, and the
  # client waits forever on a zombie. The patch extracts the WNOHANG reap loop
  # into `reap_children` and calls it once right after `thread_block()`,
  # keeping 0.7.0's exit-code semantics (a signalled init reports the bare
  # signal number). Upstream's commit c06504aa7e on main (youki-dev/youki#3639,
  # 2026-08-27) CONTAINS this fix as part of a larger foreground-PTY change; it
  # is unreleased as of 2026-09-23 (the 0.7.1 release PR, #3666, is open). DROP
  # THIS PATCH when re-pinning to a release that contains that commit — and note
  # that upstream there reports a signalled init as 128+signal where this
  # backport keeps the bare signal. Nothing in kata decodes it:
  # `kata-provider-youki` forwards `youki run`'s exit code verbatim as the
  # stage's (`Watched::Exited`) and discards it on cancellation and when the
  # client did not finish its own delete (`Watched::ClientFailed`), so the re-pin
  # changes the number a signal-killed stage reports (9 -> 137) and nothing
  # else. runc had the same bug (#5208, fixed by #5210 in
  # 1.4.2); crun blocks signals before creating the process and pre-reaps.
  #
  # youki 0.7.0's torn state.json, closed at the source. `State::save` opened
  # `state.json` with `O_TRUNC` and wrote through a `BufWriter`, and
  # `Container::start` releases the init BEFORE saving `running`, so any
  # concurrent reader (`youki kill`, `state`, `list`, `delete`) could open a
  # 0-byte or partial document and fail to parse it. The second patch writes a
  # pid-named temporary file beside it, fsyncs it, and renames it into place:
  # a reader sees the previous document or the new one, never a torn one, and a
  # writer killed mid-save leaves the previous one. It does NOT order concurrent
  # writers (the last rename wins — see `kata-provider-youki`'s `cancel` for why
  # kata's teardown does not depend on which), does not sync the directory, and
  # leaves a killed writer's temporary file for `delete` to remove with the
  # container directory. Upstream 0.7.0 has no equivalent.
  patches = (old.patches or [ ]) ++ [
    ./youki-0.7.0-foreground-prereap.patch
    ./youki-0.7.0-atomic-state-save.patch
  ];
  cargoBuildFlags = [
    "-p"
    "youki"
    "--features"
    "systemd,seccomp"
  ];
  # The check phase gets the SAME feature set, so the derivation tests what it
  # ships. nixpkgs' `cargoTestFlags = [ "-p" "youki" ]` would compile a second,
  # libseccomp-less `youki` for `cargo test` and prove nothing about the binary
  # that lands in `$out`.
  cargoTestFlags = [
    "-p"
    "youki"
    "--features"
    "systemd,seccomp"
  ];
  # The check phase runs ONE test at a time (`RUST_TEST_THREADS=1`), because
  # 0.7.0's suite forks from test threads while other test threads mutate the
  # environment. `rootpath::tests::test_determine_root_path_rootless` calls
  # `std::env::set_var`/`remove_var`, which hold std's process-wide ENV_LOCK for
  # writing; the `observability::tests` cells fork through
  # `libcontainer::test_utils::test_in_child_process`, and the child's first act
  # is `tempfile::tempdir()`, which reads `TMPDIR` under that lock. A fork that
  # lands while another thread holds it gives a child whose copy of the lock is
  # held by a thread that does not exist in it: the child sleeps on the futex
  # forever and the parent sleeps in `recv` on its channel — a build that never
  # ends. Seen as `observability::tests::test_init_many_times` at 0% CPU for 30
  # minutes on 1 of 3 fresh hosts. Serial tests leave only libtest's main thread,
  # parked in `recv`, beside a fork, so every forking test is covered — not just
  # the one seen hanging — and no test is skipped.
  dontUseCargoParallelTests = true;
})
