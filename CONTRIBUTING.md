# Contributing

kata is pre-1.0 and changes quickly; open an issue before a larger change.
Report security issues as described in [SECURITY.md](SECURITY.md).

## Setup and checks

Linux x86-64 only. `nix develop` provides `just`, `cargo-nextest`,
`cargo-deny`, `git`, `python3`, the pinned ruff, jj, `cargo-sweep` (the
age bound on the gate's and the nightly's target dirs) and a musl C compiler as
`x86_64-linux-musl-gcc` (the push tier's static in-capsule `kata`). Builds and clippy use
the stable Rust `rust-toolchain.toml` pins (kata tracks the latest stable). You
also need rustup with the nightly named in `.config/audit-nightly` (plus
rustfmt): `just fmt` runs `cargo +<nightly>`, which only rustup's `cargo`
accepts, so keep `~/.cargo/bin` first on `PATH`. `just host-check` reports a
missing nightly, a missing or unpinned ruff and a missing jj or one older than the
jj-lib `Cargo.lock` pins, and refuses a host where the
filesystem holding `target/`, `$TMPDIR` or `$HOME` is 80% full or more. Tests run under
cargo-nextest; never `cargo test`. The test recipes (`just test`, `test-crate`,
`test-one-crate`, `test-one`, `youki-pin-cells`) give the suite a `TMPDIR` on a tmpfs —
`$XDG_RUNTIME_DIR`, which a login session has, or a tmpfs directory this uid owns at 0700
that `KATA_TEST_TMPFS` names — with 2 GiB available, and refuse a host without one
(`just host-check` reports it too), so the suite's tempdirs never sit behind a disk's
flush.

- `just gate`: format, lint, `cargo deny`, tests, doctests and conformance.
  Needs no containment capability. Run it before opening a pull request.
- `just gate-push`, `just oci-live-smoke`: need a host that meets the README's
  requirements. Maintainers run these before merging.

## Commits and license

One imperative sentence as the subject, then a body saying what changed and
why. A bug fix comes with a test that fails without it. Contributions are dual
licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), as the
README describes.
