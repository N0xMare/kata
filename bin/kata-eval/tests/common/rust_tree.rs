//! The workspace's Rust targets and the module tree under each, read from manifests
//! and sources only: `cargo metadata --no-deps` and `syn`, never a build.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Lib,
    Bin,
    Test,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::Lib => "lib",
            TargetKind::Bin => "bin",
            TargetKind::Test => "test",
        }
    }
}

#[derive(Debug)]
pub struct Target {
    pub name: String,
    pub kind: TargetKind,
    pub src_path: PathBuf,
}

/// Package name → its lib, bin and test targets, from `cargo metadata --no-deps`
/// (manifests only: no build, no resolution, no lockfile write).
pub fn workspace_targets(root: &Path) -> BTreeMap<String, Vec<Target>> {
    let output = Command::new(env!("CARGO"))
        .current_dir(root)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--offline",
        ])
        .output()
        .unwrap_or_else(|error| panic!("running `cargo metadata`: {error}"));
    assert!(
        output.status.success(),
        "`cargo metadata --no-deps` failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: Value = serde_json::from_slice(&output.stdout).expect("cargo metadata JSON");
    let mut packages = BTreeMap::new();
    for package in metadata["packages"].as_array().expect("metadata packages") {
        let name = package["name"].as_str().expect("package name").to_string();
        let mut targets = Vec::new();
        for target in package["targets"].as_array().expect("package targets") {
            let kinds: Vec<&str> = target["kind"]
                .as_array()
                .expect("target kind")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            let kind = if kinds.contains(&"test") {
                TargetKind::Test
            } else if kinds.contains(&"bin") {
                TargetKind::Bin
            } else if kinds
                .iter()
                .any(|kind| matches!(*kind, "lib" | "rlib" | "proc-macro"))
            {
                TargetKind::Lib
            } else {
                continue;
            };
            targets.push(Target {
                name: target["name"].as_str().expect("target name").to_string(),
                kind,
                src_path: PathBuf::from(target["src_path"].as_str().expect("src_path")),
            });
        }
        packages.insert(name, targets);
    }
    packages
}

/// Where a module's children live, per the reference's module-path rules.
pub struct ModuleDirs {
    /// Where `mod x;` looks for `x.rs` / `x/mod.rs`.
    pub children: PathBuf,
    /// What a `#[path = "..."]` on a child is relative to.
    pub path_base: PathBuf,
}

#[derive(Default)]
pub struct SourceCache {
    files: BTreeMap<PathBuf, Result<syn::File, String>>,
}

impl SourceCache {
    pub fn parse(&mut self, path: &Path) -> Result<&syn::File, String> {
        self.files
            .entry(path.to_path_buf())
            .or_insert_with(|| {
                let text = std::fs::read_to_string(path)
                    .map_err(|error| format!("reading {}: {error}", path.display()))?;
                syn::parse_file(&text)
                    .map_err(|error| format!("parsing {}: {error}", path.display()))
            })
            .as_ref()
            .map_err(Clone::clone)
    }
}

pub fn path_attribute(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("path") {
            return None;
        }
        let syn::Meta::NameValue(pair) = &attr.meta else {
            return None;
        };
        match &pair.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(path),
                ..
            }) => Some(path.value()),
            _ => None,
        }
    })
}

pub fn is_test_attribute(attr: &syn::Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "test")
}

/// Where a declared module's items come from, and where ITS children live.
pub enum ModuleSource<'a> {
    /// `mod name { ... }`.
    Inline(&'a [syn::Item], ModuleDirs),
    /// `mod name;`: a `#[path]` file, else `name.rs`, else `name/mod.rs`.
    File(PathBuf, ModuleDirs),
}

/// Resolve `declared`, a module item found in a file whose children live per `dirs`,
/// by the reference's module-path rules.
pub fn module_source<'a>(dirs: &ModuleDirs, declared: &'a syn::ItemMod) -> ModuleSource<'a> {
    let module = declared.ident.to_string();
    if let Some((_, inline)) = &declared.content {
        return ModuleSource::Inline(
            inline,
            ModuleDirs {
                children: dirs.children.join(&module),
                path_base: dirs.children.join(&module),
            },
        );
    }
    if let Some(path) = path_attribute(&declared.attrs) {
        let child = dirs.path_base.join(path);
        let dir = child
            .parent()
            .expect("a module file has a directory")
            .to_path_buf();
        return ModuleSource::File(
            child,
            ModuleDirs {
                children: dir.clone(),
                path_base: dir,
            },
        );
    }
    let flat = dirs.children.join(format!("{module}.rs"));
    if flat.is_file() {
        let dir = flat.parent().expect("directory").to_path_buf();
        return ModuleSource::File(
            flat,
            ModuleDirs {
                children: dir.join(&module),
                path_base: dir,
            },
        );
    }
    let nested = dirs.children.join(&module).join("mod.rs");
    let dir = nested.parent().expect("directory").to_path_buf();
    ModuleSource::File(
        nested,
        ModuleDirs {
            children: dir.clone(),
            path_base: dir,
        },
    )
}

/// The module directories of a crate root at `src_path`.
pub fn root_dirs(src_path: &Path) -> ModuleDirs {
    let dir = src_path
        .parent()
        .expect("a source file has a directory")
        .to_path_buf();
    ModuleDirs {
        children: dir.clone(),
        path_base: dir,
    }
}
