// The contents of this file have been copied, for the most part,
// from the Rust compiler's bootstrap script.
// https://github.com/rust-lang/rust/blob/master/src/bootstrap/src/core/download.rs

use std::fs::{self, File};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};

use anyhow::Result;
use path_macro::path;
use rustc_version::VersionMeta;
use xshell::{cmd, Cmd, Shell};
use xz2::bufread::XzDecoder;

use crate::utils;

static CURL_FLAGS: &[&str] = &[
    // follow redirect
    "--location",
    // timeout if speed is < 10 bytes/sec for > 30 seconds
    "--speed-time",
    "30",
    "--speed-limit",
    "10",
    // timeout if cannot connect within 30 seconds
    "--connect-timeout",
    "30",
    // if there is an error, don't restart the download,
    // instead continue where it left off.
    "--continue-at",
    "-",
    // retry up to 3 times.  note that this means a maximum of 4
    // attempts will be made, since the first attempt isn't a *re*try.
    "--retry",
    "3",
    // show errors, even if --silent is specified
    "--show-error",
    // set timestamp of downloaded file to that of the server
    "--remote-time",
    // fail on non-ok http status
    "--fail",
];

fn extract_curl_version(out: &[u8]) -> semver::Version {
    let out = String::from_utf8_lossy(out);
    // The output should look like this: "curl <major>.<minor>.<patch> ..."
    out.lines()
        .next()
        .and_then(|line| line.split(" ").nth(1))
        .and_then(|version| semver::Version::parse(version).ok())
        .unwrap_or(semver::Version::new(1, 0, 0))
}

fn curl_version(sh: &Shell) -> semver::Version {
    let curl = cmd!(sh, "curl -V");
    let Ok(out) = curl.output() else { return semver::Version::new(1, 0, 0) };
    let out = out.stdout;
    extract_curl_version(&out)
}

fn download_file(sh: &Shell, url: String, destination: &Path, help_on_error: &str) {
    let mut curl: Cmd<'_> = cmd!(sh, "curl");
    curl = curl.args([
        // output file
        "--output",
        destination.to_str().unwrap(),
    ]);
    curl = curl.args(CURL_FLAGS);
    curl = curl.arg(url);

    if utils::is_running_on_ci() {
        curl = curl.arg("--silent");
    } else {
        curl = curl.arg("--progress-bar");
    }
    // --retry-all-errors was added in 7.71.0, don't use it if curl is old.
    if curl_version(sh) >= semver::Version::new(7, 71, 0) {
        curl = curl.arg("--retry-all-errors");
    }
    if curl.quiet().run().is_err() {
        if !help_on_error.is_empty() {
            eprintln!("{help_on_error}");
        }
        std::process::exit(1);
    }
}

fn unpack(tarball: &Path, dst: &Path, pattern: &str) -> Result<()> {
    if !dst.exists() {
        std::fs::create_dir_all(dst)?;
    }
    // `tarball` ends with `.tar.xz`; strip that suffix
    // example: `rust-dev-nightly-x86_64-unknown-linux-gnu`
    let uncompressed_filename =
        Path::new(tarball.file_name().expect("missing tarball filename")).file_stem().unwrap();
    let directory_prefix = Path::new(Path::new(uncompressed_filename).file_stem().unwrap());

    // decompress the file
    let data = File::open(tarball)?;
    let decompressor = XzDecoder::new(BufReader::new(data));
    let mut tar = tar::Archive::new(decompressor);

    for member in tar.entries()? {
        let mut member = member?;
        let original_path = member.path()?.into_owned();
        if original_path == directory_prefix {
            continue;
        }
        let mut short_path = original_path.strip_prefix(directory_prefix)?;
        short_path = short_path.strip_prefix(pattern).unwrap_or(short_path);
        let dst_path = dst.join(short_path);

        if !member.unpack_in(dst)? {
            panic!("path traversal attack ??");
        }
        let src_path = dst.join(original_path);
        if src_path.is_dir() && dst_path.exists() {
            continue;
        }
        move_file(src_path, dst_path)?;
    }
    let dst_dir = dst.join(directory_prefix);
    if dst_dir.exists() {
        fs::remove_dir_all(&dst_dir)?;
    }
    Ok(())
}

/// Rename a file if from and to are in the same filesystem or
/// copy and remove the file otherwise
fn move_file<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> io::Result<()> {
    match fs::rename(&from, &to) {
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            std::fs::copy(&from, &to)?;
            std::fs::remove_file(&from)
        }
        r => r,
    }
}

pub fn download_rust_dev_artifacts(
    sh: &Shell,
    meta: &VersionMeta,
    root_dir: &Path,
    artifact_url: &str,
) -> Result<PathBuf> {
    let dest_path = path!(root_dir / "rust-dev");
    // Check to see if we have already downloaded the rust-dev artifact.
    // If the version of the artifact matches the current version of our
    // toolchain, then we can reuse it. Otherwise, we should remove it and
    // download a new one.
    let latest_version = &meta.short_version_string;
    let cached_version = path!(dest_path / "version");
    if cached_version.exists() {
        let cached_version = fs::read_to_string(cached_version)?;
        // we use contains here, because the version string stored in
        // VersionMeta contains the prefix 'rustc'.
        if latest_version.contains(&cached_version) {
            return Ok(dest_path);
        } else {
            fs::remove_dir_all(&dest_path)?;
        }
    }

    let sha = &(meta.commit_hash.as_ref().unwrap());

    let channel = match &meta.channel {
        rustc_version::Channel::Dev => "dev",
        rustc_version::Channel::Nightly => "nightly",
        rustc_version::Channel::Beta => "beta",
        rustc_version::Channel::Stable => "stable",
    };

    let filename = format!("rust-dev-{}-{}.tar.xz", channel, &meta.host);
    let tarball_dest = path!(filename);
    let help_on_error = "ERROR: failed to download pre-built rust-dev artifacts.";
    download_file(sh, format!("{artifact_url}/{sha}/{filename}"), &tarball_dest, help_on_error);
    unpack(&tarball_dest, &dest_path, "rust-dev")?;
    fs::remove_file(tarball_dest)?;
    Ok(dest_path)
}
