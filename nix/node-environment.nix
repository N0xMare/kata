# The ONE Nix closure an `oci` node binds: the container tools a capsule's
# `sh`/`env`/`getent` substrate runs on, realised as store paths and named in
# the node's `[node] environment` declaration. An agent capsule needs nothing
# more: the embedded harness's model calls leave from the worker, and its tool
# calls run on this same substrate.
#
# WHY THIS FILE EXISTS. A capsule sees ONLY the declared closure: no host
# `PATH`, no `/etc`. The four roots below are the smallest environment the
# shipped OCI path needs — every stage runs through `sh`, name lookups need
# `getent`, VCS effects call `git`, TLS clients need a trust store.
#
# HOW TO REALIZE IT, from the kata checkout (the exact command `just
# node-environment` runs):
#
#     nix build -o .kata/node-environment -f nix/node-environment.nix
#
# The result is a `linkFarm` of symlinks — one per declared ROOT — whose only
# purpose is to make `nix build` realise every root in one step and to give
# the realised closure an indirect GC root so the pinned bytes survive `nix
# store gc`. `[node] environment.store_paths` still names the real roots, not
# the farm.
#
# THE ROOTS, in PATH order. Each becomes one `store_paths` entry and (when it
# ships a `bin/`) one `path_prepend` entry.
#
#   * busybox+getent: the capsule's `sh`/`env`/`getent` substrate.
#   * gitMinimal: the VCS binary every stage calls (`gitMinimal`, not `git` —
#     no perl/python script suite inside a container that runs one binary per
#     argv[0]; clone/fetch/worktree/commit are all the core binary).
#   * cacert: the ONLY trust store in the container — the rootfs carries no
#     `/etc/ssl`, so a TLS client has no default roots to find. It carries no
#     `bin/`, and kata renders no CA path into any capsule: a stage's command
#     names `${cacert}/etc/ssl/certs/ca-bundle.crt` itself.
#
# `pkgs` is an argument so the flake passes ITS nixpkgs (the same pinned
# revision — flake.lock records it) instead of this file fetching a second
# copy. The default keeps `nix build -f nix/node-environment.nix` working,
# which `just node-environment` invokes.
{
  pkgs ? import (import ./nixpkgs-pin.nix) {
    system = builtins.currentSystem;
  },
}:

let
  inherit (pkgs) lib;

  busybox = pkgs.pkgsStatic.busybox;
  getent = pkgs.pkgsStatic.getent;
  git = pkgs.gitMinimal;
  cacert = pkgs.cacert;

  roots = [
    busybox
    getent
    git
    cacert
  ];

  withBin = [
    busybox
    getent
    git
  ];
  path-prepend = map (root: "${root}/bin") withBin;

  render = import ./node-environment-toml.nix { inherit pkgs; };
  node-environment-toml = render {
    label = "kata-tools";
    nixpkgs-attribute = "kata#nix/node-environment.nix (nixpkgs b6c98e9e)";
    inherit roots path-prepend;
  };
in
(pkgs.linkFarm "kata-node-environment-roots" (
  lib.imap0 (index: root: {
    # `unsafeDiscardStringContext` because the NAME is a label, not a
    # reference: without it the `name` string carries a dependency on the
    # derivation's own outPath, which Nix refuses in a store object name.
    name = "root-${toString index}-${lib.strings.unsafeDiscardStringContext (baseNameOf (toString root))}";
    path = root;
  }) roots
)).overrideAttrs
  (old: {
    passthru = (old.passthru or { }) // {
      inherit
        roots
        path-prepend
        node-environment-toml
        ;
    };
  })
