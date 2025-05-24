use std::ffi::{OsStr, OsString};
use std::fs::{self, canonicalize};
use std::path::{Path, PathBuf};
use std::process::exit;

use anyhow::{Context, Result};
use path_macro::path;
use rustc_version::VersionMeta;
use serde::Deserialize;
use xshell::{cmd, Cmd, Shell};

use crate::downloads::download_rust_dev_artifacts;

#[inline]
pub fn is_running_on_ci() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok_and(|e| e == "true")
}

pub fn root_dir() -> std::io::Result<PathBuf> {
    const BSAN_SCRIPT_ROOT_DIR: &str = env!("CARGO_MANIFEST_DIR");
    Ok(canonicalize(BSAN_SCRIPT_ROOT_DIR)?.parent().unwrap().into())
}

/// Queries the active toolchain for the repository.
pub fn active_toolchain() -> Result<String> {
    let sh = Shell::new()?;
    sh.change_dir(root_dir()?);
    let stdout = cmd!(sh, "rustup show active-toolchain").read()?;
    Ok(stdout.split_whitespace().next().context("Could not obtain active Rust toolchain")?.into())
}

pub fn flagsplit(flags: &str) -> Vec<String> {
    // This code is taken from `RUSTFLAGS` handling in cargo.
    flags.split(' ').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

#[allow(dead_code)]
pub struct BsanEnv {
    /// The root of the repository checkout we are working in.
    pub root_dir: PathBuf,
    /// The installation directory for rust dev artifacts
    pub rust_dev: PathBuf,
    /// The shell we use.
    pub sh: Shell,
    /// Repository-wide configuration
    config: BsanConfig,
    /// active_toolchain is passed as `+toolchain` argument to cargo/rustc invocations.
    toolchain: String,
    /// Extra flags to pass to cargo.
    cargo_extra_flags: Vec<String>,
    /// Additional version metadata from rustc
    pub meta: VersionMeta,
}

#[derive(Deserialize)]
struct BsanConfig {
    artifact_url: String,
}

impl BsanConfig {
    fn from_file(path: &Path) -> Result<BsanConfig> {
        let contents: String = std::fs::read_to_string(path)?;
        let contents: BsanConfig = toml::from_str(&contents)?;
        Ok(contents)
    }
}

impl BsanEnv {
    pub fn new() -> Result<Self> {
        let toolchain = active_toolchain()?;
        let sh = Shell::new()?;
        let root_dir = root_dir()?;

        let config = BsanConfig::from_file(&path!(root_dir / "bsan.toml"))?;

        let target_output = cmd!(sh, "rustc +{toolchain} --version --verbose").quiet().read()?;
        let meta: VersionMeta = rustc_version::version_meta_for(&target_output)?;

        let rust_dev = download_rust_dev_artifacts(&sh, &meta, &root_dir, &config.artifact_url)?;

        // Hard-code the target dir, since we rely on all binaries ending up in the same spot.
        sh.set_var("CARGO_TARGET_DIR", path!(root_dir / "target"));

        // Compute rustflags.
        let rustflags = {
            let mut flags = OsString::new();
            // Add user-defined flags.
            if let Some(value) = std::env::var_os("RUSTFLAGS") {
                flags.push(" ");
                flags.push(value);
            }
            flags
        };

        sh.set_var("RUSTFLAGS", rustflags);
        // Get extra flags for cargo.
        let cargo_extra_flags = std::env::var("CARGO_EXTRA_FLAGS").unwrap_or_default();
        let mut cargo_extra_flags = flagsplit(&cargo_extra_flags);
        if cargo_extra_flags.iter().any(|a| a == "--release" || a.starts_with("--profile")) {
            // This makes binaries end up in different paths, let's not do that.
            eprintln!(
                "Passing `--release` or `--profile` in `CARGO_EXTRA_FLAGS` will totally confuse bsan-script, please don't do that."
            );
            exit(1);
        }
        // Also set `-Zroot-dir` for cargo, to print diagnostics relative to the miri dir.
        cargo_extra_flags.push(format!("-Zroot-dir={}", root_dir.display()));
        Ok(Self { sh, root_dir, config, toolchain, cargo_extra_flags, meta, rust_dev })
    }

    pub fn with_rust_flags<F>(&mut self, flags: &[&str], f: F) -> Result<()>
    where
        F: Fn(&mut BsanEnv) -> Result<()>,
    {
        let prev_flags = self.sh.var("RUSTFLAGS").ok().unwrap();
        let mut curr_flags = prev_flags.clone();
        for flag in flags {
            curr_flags.push(' ');
            curr_flags.push_str(flag);
        }
        self.sh.set_var("RUSTFLAGS", curr_flags);
        f(&mut *self)?;
        self.sh.set_var("RUSTFLAGS", prev_flags);
        Ok(())
    }

    fn cargo_cmd(&self, crate_dir: impl AsRef<OsStr>, cmd: &str) -> Cmd<'_> {
        let BsanEnv { cargo_extra_flags, .. } = self;
        let manifest_path = path!(self.root_dir / crate_dir.as_ref() / "Cargo.toml");
        self.cargo_cmd_base(cmd)
            .arg(format!("--manifest-path={}", manifest_path.display()))
            .args(cargo_extra_flags)
    }

    fn cargo_cmd_base(&self, cmd: &str) -> Cmd<'_> {
        let BsanEnv { toolchain, .. } = self;
        cmd!(self.sh, "cargo +{toolchain} {cmd}").quiet()
    }

    pub fn fmt(&self, args: &[String], check: bool) -> Result<()> {
        let mut cmd = self.cargo_cmd_base("fmt").args(args);
        if check && !args.iter().any(|s| s.as_str() == "--check") {
            cmd = cmd.arg("--check");
        };
        cmd.run()?;
        Ok(())
    }

    pub fn check(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        self.cargo_cmd(crate_dir, "check").arg("--all-targets").args(args).run()?;
        Ok(())
    }

    pub fn doc(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        let mut cmd = self.cargo_cmd(crate_dir, "doc").args(args);
        if !args.iter().any(|s| s.as_str() == "--no-deps") {
            cmd = cmd.arg("--no-deps");
        };
        cmd.run()?;
        Ok(())
    }

    pub fn clippy(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        self.cargo_cmd(crate_dir, "clippy").arg("--all-targets").args(args).run()?;
        Ok(())
    }

    pub fn test(&self, crate_dir: impl AsRef<OsStr>, args: &[String]) -> Result<()> {
        self.cargo_cmd(crate_dir, "test").args(args).run()?;
        Ok(())
    }

    pub fn build(&self, crate_dir: impl AsRef<OsStr>, args: &[String], quiet: bool) -> Result<()> {
        let quiet_flag = if quiet { Some("--quiet") } else { None };
        // We build all targets, since building *just* the bin target does not include
        // `dev-dependencies` and that changes feature resolution. This also gets us more
        // parallelism in `./b test` as we build BorrowSanitizer and its tests together.
        let mut cmd =
            self.cargo_cmd(crate_dir, "build").args(&["--all-targets"]).args(quiet_flag).args(args);
        cmd.set_quiet(quiet);
        cmd.run()?;
        Ok(())
    }

    pub fn build_llvm_pass(&mut self) -> Result<()> {
        let rust_dev_dir = &self.rust_dev;
        let bin_dir = path!(rust_dev_dir / "bin");
        let llvm_config = path!(bin_dir / "llvm-config");
        let cxxflags = cmd!(&self.sh, "{llvm_config}").arg("--cxxflags").output()?.stdout;

        let mut cfg = cc::Build::new();
        cfg.warnings(false);

        for flag in String::from_utf8(cxxflags)?.split_whitespace() {
            cfg.flag(flag);
        }

        let out_dir = path!(&self.root_dir / "target" / "bsan_pass");
        if !out_dir.exists() {
            fs::create_dir(&out_dir)?;
        }

        let src_dir = path!(&self.root_dir / "bsan-pass");
        cfg.file(path!(src_dir / "BorrowSanitizer.cpp"))
            .include(src_dir)
            .cpp(true)
            .cpp_link_stdlib(None) // we handle this below
            .out_dir(out_dir)
            .target(&self.meta.host)
            .host(&self.meta.host)
            .opt_level(0)
            .warnings_into_errors(true)
            .compile("bsan-pass");

        Ok(())
    }
}
