# The ONE renderer for a `[node] environment` TOML declaration — the shape
# `NodeEnvironmentConfig` (`crates/types/src/config.rs`) deserializes and
# `kata host setup` merges into a kata.toml.
#
# The shipped `share/kata/node-environment.toml` (the container-tools closure
# `nix/node-environment.nix` evaluates) and the declaration `just
# node-environment` prints both render through here, so they can never drift
# into two spellings of the same contract.
#
# The fields are the config's own: `label` is the operator-facing name the
# manifest records; `nixpkgs-attribute` is provenance, not a resolvable ref —
# `store_paths` carries the realised roots because a declaration must not
# depend on a registry at boot (the provenance rule in
# `NodeEnvironmentConfig`'s docs). `integrity_policy` is the policy the
# shipped environments certify under: paths are admitted by content, not by a
# trusted-signer list.
#
# THE FORM IS LOAD-BEARING. The declaration is a `[node.environment]` TABLE,
# not the `environment = { … }` inline table the doc examples abbreviate: an
# inline table may not span lines under TOML 1.0 (the `toml` crate the config
# deserializes through — `toml_edit`'s 1.1 tolerance accepts the multi-line
# form, which is how a config kata itself wrote once failed its own parse).
# Under the table form every array may still break lines, and the
# `integrity_policy` inline table stays on its own single line.
{ pkgs }:

{
  label,
  nixpkgs-attribute,
  roots,
  path-prepend,
}:

let
  inherit (pkgs) lib;
  quote = path: "\"${toString path}\"";
  rendered-paths = lib.concatMapStringsSep ", " quote roots;
  rendered-prepend = lib.concatMapStringsSep ", " quote path-prepend;
in
''
  [node]
  [node.environment]
  label = "${label}"
  system = "${pkgs.stdenv.hostPlatform.system}"
  nixpkgs_attribute = "${nixpkgs-attribute}"
  store_paths = [${rendered-paths}]
  path_prepend = [${rendered-prepend}]
  integrity_policy = { verify = "nar_hash_only", sigs_needed = 0, required_signers = [], allow_unsigned_content_addressed = true, verify_contents_at_declare = true }
''
