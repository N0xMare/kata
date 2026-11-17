# The ONE nixpkgs revision the standalone (`nix build -f`) invocations of
# nix/youki.nix and nix/node-environment.nix default to — the same revision
# the flake's `inputs.nixpkgs` locks in flake.lock
# (b6c98e9e6633ee64753b594ff4a5febf0367fc00, 2026-09-22). One revision for the
# whole node: two revisions would bind two glibcs and two runtimes.
#
# A bump is an EDIT HERE AND IN flake.nix's `inputs.nixpkgs.url` together,
# never a silent change to the bytes AppArmor is asked to cover: the youki
# store path config/youki-pin.toml names is realized from exactly this
# revision, and the flake's `checks.youki-pin` fails if the two pins move
# apart.
builtins.fetchTarball {
  url = "https://github.com/NixOS/nixpkgs/archive/b6c98e9e6633ee64753b594ff4a5febf0367fc00.tar.gz";
  sha256 = "0rzfmis9kwly6af9zdxsnb90zfnvl4mqwkbd62g9g1q6i6vfi5a2";
}
