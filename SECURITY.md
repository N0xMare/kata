# Security policy

kata runs shell commands and coding agents inside rootless OCI capsules. A way
around that containment is a security bug.

## Reporting

Report privately via GitHub: the repository's **Security** tab →
**Report a vulnerability**. Include the kata commit, your host (kernel,
distribution, AppArmor state) and steps to reproduce. Do not open a public
issue.

## Supported versions

kata is pre-1.0; only the latest release and `main` receive fixes.

## Scope

In scope: capsule escape, host credentials reaching a capsule, record or log,
cache poisoning, host file access outside a stage's declared view, and any
documented refusal that does not refuse what it claims.

Out of scope: bugs in a model provider's service, youki, the kernel or Nix
that kata does not make worse (report upstream), and hosts that do not meet the
README's requirements.
