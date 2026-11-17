{
  description = "kata — an agentic code-execution workflow engine (Linux x86-64, rootless youki)";

  # The kata binary cache. Pushed by `just cache-push` (kata's own outputs and
  # the patched youki ONLY).
  nixConfig = {
    extra-substituters = [ "https://katacode.cachix.org" ];
    extra-trusted-public-keys = [ "katacode.cachix.org-1:F9Q2oVULvBhPpfp9CmEeD/aHy5i2JMkHK83C/HISZIU=" ];
  };

  inputs = {
    # The SAME revision nix/youki.nix and nix/node-environment.nix pin today:
    # the youki derivation's store path is what config/youki-pin.toml names, so
    # moving the pin here must not move the bytes. `github:` fetches the same
    # archive tarball those files' `builtins.fetchTarball` pins.
    nixpkgs.url = "github:NixOS/nixpkgs/b6c98e9e6633ee64753b594ff4a5febf0367fc00";
    # nixpkgs at that revision carries rustc 1.98 only; the workspace pins the
    # latest stable (rust-toolchain.toml) and fmt the dated nightly
    # .config/audit-nightly names, so both come from rust-overlay. Its lock must
    # be at least as new as the stable release rust-toolchain.toml names.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      inherit (pkgs) lib;

      # The pinned stable rust-toolchain.toml names (components rustfmt+clippy,
      # the x86_64-unknown-linux-musl target kata-toolhost and the factory
      # smokes' in-capsule kata are built static for, minimal profile): it
      # builds packages.kata, the static toolhost inside it (`kataToolhost`),
      # runs clippy, and is `packages.rust-toolchain`, the cargo and rustc the
      # factory smokes' capsules build this workspace with.
      toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      # pkgsStatic's musl C compiler: kata-toolhost's musl linker, and in the
      # dev shell the `x86_64-linux-musl-gcc` cc-rs looks for when a C
      # dependency (SQLite, ring, zstd, QuickJS) builds for the musl target.
      muslCc = pkgs.pkgsStatic.stdenv.cc;
      muslCcForCcRs = pkgs.writeShellScriptBin "x86_64-linux-musl-gcc" ''
        exec ${muslCc}/bin/${muslCc.targetPrefix}cc "$@"
      '';
      # The dated nightly `just fmt` runs rustfmt under, named by
      # .config/audit-nightly (e.g. "nightly-2026-06-30").
      auditNightlyName = lib.strings.trim (builtins.readFile ./.config/audit-nightly);
      auditNightlyDate = lib.strings.removePrefix "nightly-" auditNightlyName;
      auditNightly =
        pkgs.rust-bin.nightly.${auditNightlyDate}.minimal.override
          {
            extensions = [ "rustfmt" ];
          };

      # The ruff `just lint` runs over scripts/, at the ONE version
      # requirements-audit.txt pins: nixpkgs at this revision carries
      # 0.16.8, whose default rule set reds 62 findings scripts/ passes clean
      # under 0.15.20. This is upstream's static musl release binary of the
      # pinned version. The fetch is NAMED by that version, so bumping the pin
      # there without the hash here moves the fixed-output path and the stale
      # hash fails the fetch; an unversioned name would let the old store path
      # satisfy it. The build then refuses a binary whose `--version` is not
      # the pin.
      ruffVersion =
        lib.removePrefix "ruff==" (
          lib.findFirst (lib.hasPrefix "ruff==") (throw "requirements-audit.txt pins no ruff") (
            lib.splitString "\n" (builtins.readFile ./requirements-audit.txt)
          )
        );
      ruffPinned =
        pkgs.runCommand "ruff-${ruffVersion}"
          {
            src = pkgs.fetchurl {
              name = "ruff-${ruffVersion}-x86_64-unknown-linux-musl.tar.gz";
              url = "https://github.com/astral-sh/ruff/releases/download/${ruffVersion}/ruff-x86_64-unknown-linux-musl.tar.gz";
              hash = "sha256-BxVWCyQCAktSmk/9bqfTgUoJDrJVpiFiWfsZKCO+Otg=";
            };
          }
          ''
            tar xzf $src
            install -Dm755 ruff-x86_64-unknown-linux-musl/ruff $out/bin/ruff
            test "$($out/bin/ruff --version)" = "ruff ${ruffVersion}"
          '';

      # The container-tools `oci` node environment: the capsule substrate a
      # node binds — static busybox+getent, gitMinimal, cacert. The
      # `node-environment-toml` passthru is what
      # `share/kata/node-environment.toml` installs and `kata host setup`
      # merges into a config.
      nodeEnv = import ./nix/node-environment.nix { inherit pkgs; };
      # The two `share/kata` declarations — `provider-members.toml` and
      # `node-environment.toml` — rendered by `nix/share.nix`, the one file a
      # checkout build's `kata host setup` realises too.
      kataShare = import ./nix/share.nix { inherit pkgs; };

      shippedBins = [
        "kata"
        "kata-worker"
      ];

      # The provider's kata-built bytes — `kata-provider-youki` and the OCI
      # hook — install as REAL FILES under `share/kata/provider-source`:
      # `kata host setup` feeds that directory to the provider store, which
      # copies a member VERBATIM — a symlink would mint a by-hash entry whose
      # contents are a link, not bytes kata owns. `bin/` carries relative
      # links to the same bytes so the executables stay on PATH; nothing
      # executes them from `bin/` (the provisioned store entry is the only
      # exec path).
      providerSourceBins = [
        "kata-provider-youki"
        "kata-oci-hook"
      ];

      # The provider entry's capsule init, `toolhost/kata-toolhost`: a nanocode
      # agent capsule execs it as PID 1 from the read-only `/.kata` bind, and
      # the capsule's root filesystem is a Nix closure plus mappings with no
      # dynamic loader, so it is built STATIC: the source install's own command
      # (`cargo build --release --locked --target x86_64-unknown-linux-musl -p
      # kata-toolhost`), with the pinned toolchain (rust-toolchain.toml names its
      # musl rust-std) and pkgsStatic's musl C compiler as the target's linker.
      # Build scripts stay on the build platform's compiler: under
      # `pkgsStatic.makeRustPlatform` every `build-script-build` died of SIGSEGV
      # (measured), so only the target's linker is pkgsStatic's. Its own
      # derivation over the same source as `kataPkg`, so the source digest it
      # states in its Hello is the one the worker compiled in.
      providerToolhost = "toolhost/kata-toolhost";
      toolhostTarget = "x86_64-unknown-linux-musl";
      kataToolhost =
        (pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        }).buildRustPackage
          {
            pname = "kata-toolhost";
            version = (lib.importTOML ./Cargo.toml).workspace.package.version;
            src = ./.;
            cargoDeps = kataCargoVendor;
            strictDeps = true;
            nativeBuildInputs = [ muslCc ];
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCc}/bin/${muslCc.targetPrefix}cc";
            buildPhase = ''
              runHook preBuild
              cargo build --release --locked --offline --target ${toolhostTarget} -p kata-toolhost
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              install -Dm755 target/${toolhostTarget}/release/kata-toolhost $out/bin/kata-toolhost
              runHook postInstall
            '';
            auditable = false;
            doCheck = false;
          };

      # The provider entry's third member, the iproute2 `ip` the hook execs,
      # is NOT copied into this package: kata's output carries only kata's own
      # code. `share/kata/provider-members.toml` (rendered by `nix/share.nix`)
      # declares the store path, so the package REFERENCES iproute2 (it is in
      # the closure, fetched from its own store path) without containing it,
      # and `kata host setup` copies `ip` verbatim from that path into the
      # provider entry. Spelled here independently of that render: it is the
      # `packaged-layout` check's expectation.
      providerIp = "${pkgs.iproute2}/bin/ip";

      installKata = targetDir: ''
        mkdir -p $out/bin $out/share/kata/provider-source
        for b in ${lib.concatStringsSep " " shippedBins}; do
          install -Dm755 ${targetDir}/$b $out/bin/$b
        done
        for b in ${lib.concatStringsSep " " providerSourceBins}; do
          install -Dm755 ${targetDir}/$b $out/share/kata/provider-source/$b
          ln -s ../share/kata/provider-source/$b $out/bin/$b
        done
        install -Dm755 ${kataToolhost}/bin/kata-toolhost $out/share/kata/provider-source/${providerToolhost}
        install -Dm644 ${kataShare}/share/kata/provider-members.toml $out/share/kata/provider-members.toml
        install -Dm644 ${kataShare}/share/kata/node-environment.toml $out/share/kata/node-environment.toml
        cp -r ${./workflows/std} $out/share/kata/workflows
        cp -r ${./workflows/examples} $out/share/kata/examples
        cp -r ${./workflows/kata-factory} $out/share/kata/kata-factory
      '';

      # cmake+perl stay on PATH for aws-lc-sys (commonware-cryptography),
      # which the workspace lock carries.
      kataNativeBuildInputs = [
        pkgs.cmake
        pkgs.perl
      ];

      # ── rustPlatform.buildRustPackage ───────────────────────────────────
      # Chosen over crane by measurement on a 128-core, single-NVMe host: one drv,
      # 286 s wall cold for the whole workspace; crane's per-crate drvs ran
      # >45 min before its package phase and still needed the whole-tree src
      # (include_str! of .star/.html/.toml defeats cleanCargoSource) plus a
      # hand-maintained dummy-source list.
      kataCargoVendor = pkgs.rustPlatform.importCargoLock {
        lockFile = ./Cargo.lock;
        # One entry per git rev in Cargo.lock: outputHashes maps a
        # name-version to that package's git REV, so one entry covers every
        # crate fetched at the same rev (all commonware-*, all nanocode-*).
        outputHashes = {
          "commonware-codec-2026.9.0" = "sha256-VZK1X0Ba+HIC0MBlf+PRzyqiV9nxQFCXG+ZEMHertec=";
          "nanocode-agent-config-0.6.7" = "sha256-NXV2apHKZ6ctoLD1N2XkE6NYe/JO6+OPOq0ATcMEhRI=";
        };
      };

      kataPkg =
        (pkgs.makeRustPlatform {
          cargo = toolchain;
          rustc = toolchain;
        }).buildRustPackage
          {
            pname = "kata";
            # The one version spelling: Cargo.toml's [workspace.package].
            version = (lib.importTOML ./Cargo.toml).workspace.package.version;
            src = ./.;
            cargoDeps = kataCargoVendor;
            strictDeps = true;
            nativeBuildInputs = kataNativeBuildInputs;
            cargoBuildFlags = [
              "--workspace"
              "--locked"
            ];
            auditable = false;
            doCheck = false;
            installPhase = installKata "target/x86_64-unknown-linux-gnu/release";
          };
    in
    {
      packages.${system} = {
        kata = kataPkg;
        default = kataPkg;
        youki = import ./nix/youki.nix { inherit pkgs; };
        # `nix/node-environment.nix`, evaluated with this flake's pkgs — the
        # container-tools `oci` substrate and the source of the packaged
        # `share/kata/node-environment.toml` render.
        node-env = nodeEnv;
        # The rust-toolchain.toml pin, lock-resolved: the in-capsule cargo and
        # rustc of `factory-self-improve-preflight-smoke` and
        # `factory-self-improve-smoke`, whose validation stages build this
        # workspace (its `rust-version` is that pin's minor release).
        rust-toolchain = toolchain;
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [
          toolchain
          auditNightly
          pkgs.just
          pkgs.cargo-nextest
          pkgs.cargo-mutants
          pkgs.cargo-deny
          # `scripts/prune-target.sh` bounds the persistent gate and nightly
          # target dirs by age with it.
          pkgs.cargo-sweep
          # The push tier's static musl `kata` (`_containment-preconditions`).
          muslCcForCcRs
          pkgs.jujutsu
          pkgs.git
          pkgs.gh
          pkgs.python3
          ruffPinned
          pkgs.cachix
        ];
      };

      checks.${system} = {
        kata-build = self.packages.${system}.kata;
        youki-pin =
          let
            pin = (builtins.fromTOML (builtins.readFile ./config/youki-pin.toml)).youki;
          in
          pkgs.runCommand "youki-pin-check" { } ''
            want=${pin.store_path}
            got=${self.packages.${system}.youki}/bin/youki
            if [ "$want" != "$got" ]; then
              echo "youki-pin-check: FAIL" >&2
              echo "  pinned store_path: $want" >&2
              echo "  packages.youki:    $got" >&2
              exit 1
            fi
            echo "youki-pin-check: $got == pinned store_path"
            touch $out
          '';
        # The layout `kata host setup` probes beside the installed binary:
        # `share/kata/provider-source` must hold the kata-built provider
        # members as REGULAR files (a symlink provisions a by-hash entry whose
        # contents are a link, not bytes kata owns — `copy_tree` copies links
        # verbatim) and NO `ip`; the package must contain no copy of the
        # iproute2 `ip` anywhere; `share/kata/provider-members.toml` must
        # declare an `ip` that is a regular executable file under the Nix
        # store; and `share/kata/node-environment.toml` must name every root
        # `.#node-env` realises — the store paths themselves are the
        # assertion, so a render that drifted from the packaged closure reds
        # here rather than at an operator's `nix-store --realise`. No
        # `workflows/smoke` rig ships, as a root or as a file.
        packaged-layout =
          let
            kata = self.packages.${system}.kata;
          in
          pkgs.runCommand "packaged-layout-check" { } ''
            for m in ${lib.concatStringsSep " " (providerSourceBins ++ [ providerToolhost ])}; do
              member=${kata}/share/kata/provider-source/$m
              if [ ! -f "$member" ] || [ -L "$member" ]; then
                echo "packaged-layout: $member is absent or not a regular file" >&2
                exit 1
              fi
              if [ ! -x "$member" ]; then
                echo "packaged-layout: $member is not executable" >&2
                exit 1
              fi
            done
            # The capsule init runs where no dynamic loader is: no PT_INTERP
            # and no NEEDED entry.
            toolhost=${kata}/share/kata/provider-source/${providerToolhost}
            if ${pkgs.binutils-unwrapped}/bin/readelf -lW "$toolhost" | grep -q 'INTERP'; then
              echo "packaged-layout: $toolhost names a program interpreter; the capsule init must be static" >&2
              exit 1
            fi
            if ${pkgs.binutils-unwrapped}/bin/readelf -dW "$toolhost" | grep -q '(NEEDED)'; then
              echo "packaged-layout: $toolhost needs a shared library; the capsule init must be static" >&2
              exit 1
            fi
            if [ -e ${kata}/share/kata/provider-source/ip ] || [ -L ${kata}/share/kata/provider-source/ip ]; then
              echo "packaged-layout: the package ships share/kata/provider-source/ip; ip is declared, not copied" >&2
              exit 1
            fi
            ipsum=$(sha256sum < ${providerIp} | cut -d' ' -f1)
            while IFS= read -r -d "" file; do
              if [ "$(sha256sum < "$file" | cut -d' ' -f1)" = "$ipsum" ]; then
                echo "packaged-layout: $file is a copy of the iproute2 ip" >&2
                exit 1
              fi
            done < <(find ${kata} -type f -print0)
            members=${kata}/share/kata/provider-members.toml
            if [ ! -f "$members" ] || [ -L "$members" ]; then
              echo "packaged-layout: $members is absent or not a regular file" >&2
              exit 1
            fi
            if [ "$(cat "$members" | grep -v '^#')" != 'ip = "${providerIp}"' ]; then
              echo "packaged-layout: $members does not declare exactly ip = \"${providerIp}\"" >&2
              exit 1
            fi
            declared=$(sed -n 's/^ip = "\(.*\)"$/\1/p' "$members")
            real=$(readlink -f "$declared")
            case "$real" in
              /nix/store/*) ;;
              *)
                echo "packaged-layout: the declared ip $declared resolves to $real, outside /nix/store" >&2
                exit 1
                ;;
            esac
            if [ ! -f "$real" ] || [ ! -x "$real" ]; then
              echo "packaged-layout: the declared ip $declared is not a regular executable file" >&2
              exit 1
            fi
            declaration=${kata}/share/kata/node-environment.toml
            for root in ${lib.concatStringsSep " " nodeEnv.passthru.roots}; do
              if ! grep -q -- "$root" "$declaration"; then
                echo "packaged-layout: $declaration does not name node-env root $root" >&2
                exit 1
              fi
            done
            # The FORM is a contract, not style: `merge_oci_config` inserts the
            # declaration verbatim and the config loader's strict TOML 1.0
            # refuses a multi-line `environment = { … }` inline table, so the
            # render must be the `[node.environment]` table.
            if ! grep -q '^\[node\.environment\]$' "$declaration"; then
              echo "packaged-layout: $declaration does not declare the [node.environment] table" >&2
              exit 1
            fi
            if grep -q 'environment = {' "$declaration"; then
              echo "packaged-layout: $declaration uses the inline-table form TOML 1.0 refuses" >&2
              exit 1
            fi
            # The gate's `workflows/smoke` rigs never ship: the package has no
            # `share/kata/smoke` root and no rig's file under any bundled root
            # (`installKata` copies `workflows/std`, not the rigs beside it).
            if [ -e ${kata}/share/kata/smoke ]; then
              echo "packaged-layout: the package ships share/kata/smoke; the smoke rigs are not a bundled root" >&2
              exit 1
            fi
            for rig in ${./workflows/smoke}/*.star; do
              shipped=$(find ${kata}/share/kata -name "$(basename "$rig")" -print -quit)
              if [ -n "$shipped" ]; then
                echo "packaged-layout: $shipped is the smoke rig $(basename "$rig"); the rigs do not ship" >&2
                exit 1
              fi
            done
            echo "packaged-layout: kata-built provider members are real executables, the capsule init static; ip is declared at $real, not copied; the declaration names every node-env root; no smoke rig ships"
            touch $out
          '';
      };
    };
}
