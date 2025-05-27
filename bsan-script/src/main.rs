// Our build script is a modified copy of Miri's build script.
#![feature(io_error_more)]
use std::path::PathBuf;

use anyhow::Result;
use clap::{command, Parser, Subcommand};
mod commands;
mod download;
mod env;
mod utils;

#[derive(Clone, Debug, Subcommand)]
pub enum Command {
    /// Ensures that all dependencies have been installed.
    Setup,
    /// Execute all tests and build steps in CI.
    Ci {
        /// Flags that are passed through to each subcommand.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
        #[arg(long)]
        quiet: bool,
    },
    /// Build BorrowSanitizer.
    Build {
        /// Flags that are passed through to `cargo build`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
        #[arg(long)]
        quiet: bool,
        #[arg(long)]
        release: bool,
    },
    /// Check BorrowSanitizer.
    Check {
        /// Flags that are passed through to `cargo check`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
    },
    /// Check components with Clippy.
    Clippy {
        /// Flags that are passed through to `cargo clippy`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
        #[arg(long)]
        check: bool,
    },
    /// Build documentation.
    Doc {
        /// Flags that are passed through to `cargo doc`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
    },
    /// Run the test suite.
    Test {
        /// Update stdout/stderr reference files.
        #[arg(long)]
        bless: bool,
        /// Flags that are passed through to the test harness.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
    },
    /// Format all sources and tests.
    Fmt {
        /// Flags that are passed through to `rustfmt`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        flags: Vec<String>,
        #[arg(long)]
        check: bool,
    },
    /// Execute a binary within the target bindir of the sysroot.
    Bin {
        binary_name: String,
        /// Args that are passed through to the executable.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Instrument an LLVM bitcode file using the BorrowSanitizer pass
    Opt {
        /// Flags that are passed through to `opt`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Installs binaries into the custom toolchain.
    Install {
        /// Flags that are passed through to `cargo install`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
        #[arg(long)]
        quiet: bool,
    },
}

#[derive(Parser)]
#[command(after_help = "Environment variables:
  CARGO_EXTRA_FLAGS: Pass extra flags to all cargo invocations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

fn main() -> Result<()> {
    let args = std::env::args();
    let args = Cli::parse_from(args);
    args.command.exec()?;
    Ok(())
}
