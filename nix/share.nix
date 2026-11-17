# The two `share/kata` declarations kata does not build with cargo, as one
# store object laid out `share/kata/<file>` — the layout `kata host setup` reads
# beside its binary:
#
#   * `provider-members.toml`: the provider-entry member kata does not build,
#     iproute2's `ip`, by Nix store path. `kata host setup` copies it verbatim
#     into the provider entry.
#   * `node-environment.toml`: the `[node.environment]` declaration of the
#     container-tools closure `nix/node-environment.nix` evaluates — the
#     default capsule environment `kata host setup` merges into a config.
#
# Both install paths read THIS file, so they cannot declare two answers:
#
#   * the flake's `kata` package copies both files into its own
#     `share/kata/` (`installKata` in flake.nix);
#   * a checkout build (`target/release/kata`, no packaged tree) has
#     `kata host setup` realise it with
#
#         nix-build --out-link .kata/nix-roots/kata-share nix/share.nix
#
#     and read the declarations from the result. The out-link is the GC root:
#     both files name store paths, so it keeps `ip` and the closure alive.
#
# `pkgs` is an argument so the flake passes ITS nixpkgs (the same pinned
# revision — flake.lock records it); the default is the standalone pin
# `nix/nixpkgs-pin.nix` names, so `nix-build` from a checkout needs no flake
# and no experimental feature.
{
  pkgs ? import (import ./nixpkgs-pin.nix) {
    system = builtins.currentSystem;
  },
}:

let
  nodeEnv = import ./node-environment.nix { inherit pkgs; };
  providerMembers = pkgs.writeText "kata-provider-members.toml" ''
    # The provider-entry member kata does not build, by Nix store path.
    # `kata host setup` copies it verbatim into the provider entry.
    ip = "${pkgs.iproute2}/bin/ip"
  '';
  nodeEnvironment = pkgs.writeText "kata-node-environment.toml" nodeEnv.passthru.node-environment-toml;
in
pkgs.runCommand "kata-share" { } ''
  install -Dm644 ${providerMembers} $out/share/kata/provider-members.toml
  install -Dm644 ${nodeEnvironment} $out/share/kata/node-environment.toml
''
