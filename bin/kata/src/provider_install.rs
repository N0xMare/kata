//! `kata sandbox install-external-provider` — provision an external provider
//! into this node's by-hash provider store and print the three exports that
//! route the node to it.
//!
//! A provider is identified by CONTENT, never by `PATH`: this command copies
//! the directory holding `kata-provider-<name>` into the store, hashes the
//! COPY, seals it, and prints the `store:<hex>` address of what it published —
//! which is the only value `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS` accepts.
//! It is the ONLY supported way to install a provider, and that is the point:
//! there is no `PATH` to drop a binary on, so a refusal that says *"install
//! the provider"* names something an operator can actually run. The capsule
//! route's provider is the only thing this surface installs.

use std::path::Path;

use serde::Serialize;

/// What an install published, in the shape `--format json` emits.
///
/// The three exports are a FIELD rather than something the human renderer
/// composes, so a machine consumer and a human reader are handed the same
/// strings — and so the keys an operator must set are generated from the
/// constants their readers own rather than typed out in a doc that can go stale.
#[derive(Debug, Serialize)]
pub struct ProviderInstallReport {
    /// The provider NAME — `KATA_EXTERNAL_EXECUTION_PROVIDER`.
    pub name: String,
    /// The minted content address — `KATA_EXTERNAL_EXECUTION_PROVIDER_ADDRESS`.
    pub address: String,
    /// The store root it was published into — `KATA_EXTERNAL_PROVIDER_STORE`.
    pub store_root: String,
    /// The published entry, `<root>/<hex>`.
    pub entry: String,
    /// The executable inside it that kata will spawn.
    pub binary: String,
    /// Regular files in the entry.
    pub files: usize,
    /// Total bytes of regular-file content hashed.
    pub bytes: u64,
    /// The exact three lines that route this node to this provider.
    pub exports: String,
}

/// **The operator-facing install story, end to end.**
///
/// kata never resolves a provider from `PATH`, so a refusal that says
/// *"install the provider"* while naming no command an operator can type would
/// be a recourse nobody can invoke; every refusal in
/// `kata_worker::provider_store` names THIS command.
///
/// # Errors
///
/// A store root that was neither passed nor exported, and whatever
/// [`kata_worker::ProviderStore::provision`] refuses (a source that is not a
/// directory, a source holding no `kata-provider-<name>`, a name the route would
/// itself refuse).
pub fn run_install_external_provider(
    name: &str,
    source: &Path,
    store: Option<&Path>,
) -> anyhow::Result<ProviderInstallReport> {
    let root = match store {
        Some(root) => root.to_path_buf(),
        None => kata_worker::declared_provider_store_root()
            .map_err(|error| anyhow::anyhow!("kata sandbox install-external-provider: {error}"))?
            .ok_or_else(|| {
            anyhow::anyhow!(
                "kata sandbox install-external-provider: no store root. Pass `--store <dir>` or \
                 export `{env}=<dir>`. This command will not choose a location on your behalf: \
                 the store root is where this node keeps provider bytes it will spawn, and a \
                 default picked here would be a path kata invented and an operator never \
                 declared.",
                env = kata_worker::EXTERNAL_PROVIDER_STORE_ENV,
            )
        })?,
    };
    let provisioned = kata_worker::ProviderStore::new(&root)
        .provision(name, source)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(ProviderInstallReport {
        exports: provisioned.operator_exports(&root),
        address: provisioned.address.to_string(),
        name: provisioned.name.clone(),
        store_root: root.display().to_string(),
        entry: provisioned.entry.display().to_string(),
        binary: provisioned.binary.display().to_string(),
        files: provisioned.files,
        bytes: provisioned.bytes,
    })
}

/// Render an install as operator-facing text. The CLI dispatch owns the
/// `--format` choice, so the human shape lives beside the report it renders.
#[must_use]
pub fn render_provider_install(report: &ProviderInstallReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "--- kata sandbox install-external-provider ---");
    let _ = writeln!(out, "provider   {}", report.name); // kata-spacing: intentional
    let _ = writeln!(out, "address    {}", report.address); // kata-spacing: intentional
    let _ = writeln!(out, "entry      {}", report.entry); // kata-spacing: intentional
    let _ = writeln!(out, "binary     {}", report.binary); // kata-spacing: intentional
    let _ = writeln!(
        out,
        "hashed     {} file(s), {} byte(s)", // kata-spacing: intentional
        report.files, report.bytes
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "Route this node to it by exporting all three:");
    let _ = writeln!(out);
    let _ = writeln!(out, "{}", report.exports);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "The address IS the bytes: replacing the provider mints a NEW address, and a node still \
         declaring the old one is REFUSED rather than silently handed the new binary. kata never \
         searches PATH for a provider."
    );
    out
}
