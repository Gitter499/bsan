use std::fs;

use anyhow::Result;
use path_macro::path;
use xshell::cmd;

use crate::env::{BsanEnv, Mode};
use crate::utils::show_error;
use crate::*;

static BSAN_RT: &str = "libbsan_rt.a";

#[cfg(target_os = "macos")]
static BSAN_PLUGIN: &str = "libbsan_plugin.dylib";

#[cfg(target_os = "linux")]
static BSAN_PLUGIN: &str = "libbsan_plugin.so";

static RT_FLAGS: &[&str] =
    &["-Cpanic=abort", "-Zpanic_abort_tests", "-Cembed-bitcode=yes", "-Clto"];

impl Command {
    pub fn exec(self) -> Result<()> {
        let mut env = BsanEnv::new()?;
        match self {
            Command::Setup => Ok(()),
            Command::Build { flags, quiet, release } => {
                Self::build(&mut env, &flags, quiet, release)
            }
            Command::Check { flags } => Self::check(&mut env, &flags),
            Command::Clippy { flags, check } => Self::clippy(&mut env, &flags, check),
            Command::Test { bless, flags } => Self::test(&mut env, &flags, bless),
            Command::Fmt { flags, check } => Self::fmt(&env, &flags, check),
            Command::Doc { flags } => Self::doc(&mut env, &flags),
            Command::Ci { flags, quiet } => Self::ci(&mut env, &flags, quiet),
            Command::Bin { binary_name, args } => Self::bin(&mut env, binary_name, &args),
            Command::Opt { args } => Self::opt(&mut env, &args),
            Command::Install { args, quiet } => Self::install(&mut env, &args, quiet),
        }
    }

    #[allow(dead_code)]
    fn install(env: &mut BsanEnv, args: &[String], quiet: bool) -> Result<()> {
        env.install("cargo-bsan", args)?;
        env.install("bsan-driver", args)?;
        Self::install_llvm_pass(env)?;
        Self::install_runtime(env, args, quiet)
    }

    fn ci(env: &mut BsanEnv, flags: &[String], quiet: bool) -> Result<()> {
        Self::fmt(env, flags, true)?;
        Self::clippy(env, flags, true)?;
        Self::build(env, flags, quiet, false)?;
        Self::doc(env, flags)?;
        Ok(())
    }

    fn fmt(env: &BsanEnv, flags: &[String], check: bool) -> Result<()> {
        env.fmt(flags, check)
    }

    fn doc(env: &mut BsanEnv, flags: &[String]) -> Result<()> {
        env.doc(".", flags)?;
        env.with_rust_flags(RT_FLAGS, |env| env.doc("bsan-rt", flags))
    }

    fn test(env: &mut BsanEnv, flags: &[String], _bless: bool) -> Result<()> {
        env.with_rust_flags(RT_FLAGS, |env| env.test("bsan-rt", flags))?;

        env.test("bsan-driver", flags)?;
        env.test("cargo-bsan", flags)?;

        Self::install(env, &vec![], false)?;

        let sysroot = cmd!(env.sh, "cargo bsan setup --print-sysroot").output()?.stdout;
        let sysroot = String::from_utf8(sysroot)?;

        env.sh.set_var("BSAN_SYSROOT", sysroot.trim());

        let cargo_home = std::env::var("CARGO_HOME")
            .expect("Unable to resolve `CARGO_HOME` environment variable.");

        let driver_binary = path!(cargo_home / "bin" / "bsan-driver");
        if !driver_binary.exists() {
            show_error!(
                "Unable to locate `bsan-driver` binary in the sysroot ({:?})",
                driver_binary.parent().unwrap()
            );
        }

        let plugin_path = path!(env.sysroot / "lib" / BSAN_PLUGIN);
        env.sh.set_var("BSAN_PLUGIN", plugin_path);
        env.sh.set_var("BSAN_RT_SYSROOT", &env.sysroot);
        env.sh.set_var("BSAN_DRIVER", driver_binary);

        cmd!(env.sh, "cargo test -p bsan --test ui").run()?;

        Ok(())
    }

    fn clippy(env: &mut BsanEnv, flags: &[String], check: bool) -> Result<()> {
        let run_clippy = |env: &mut BsanEnv| {
            env.clippy(".", flags)?;
            env.with_rust_flags(RT_FLAGS, |env| env.clippy("bsan-rt", flags))
        };
        if check {
            env.with_rust_flags(&["-Dwarnings"], run_clippy)
        } else {
            run_clippy(env)
        }
    }

    fn check(env: &mut BsanEnv, flags: &[String]) -> Result<()> {
        env.check(".", flags)?;
        env.with_rust_flags(RT_FLAGS, |env| env.check("bsan-rt", flags))
    }

    fn build(env: &mut BsanEnv, flags: &[String], quiet: bool, release: bool) -> Result<()> {
        env.in_mode(Mode::release(release), |env| {
            Self::build_llvm_pass(env)?;
            env.build(".", flags, false)?;
            Self::build_runtime(env, flags, quiet)?;
            Ok(())
        })
    }

    pub fn build_llvm_pass(env: &mut BsanEnv) -> Result<PathBuf> {
        let cxxflags = env.llvm_config().arg("--cxxflags").output()?.stdout;

        let mut cfg = env.cc();
        cfg.warnings(false);

        for flag in String::from_utf8(cxxflags)?.split_whitespace() {
            cfg.flag(flag);
        }

        let out_dir = env.artifact_dir();
        fs::create_dir_all(&out_dir)?;

        let src_dir = path!(&env.root_dir / "bsan-pass");

        let objects = cfg
            .file(path!(src_dir / "BorrowSanitizer.cpp"))
            .include(src_dir)
            .cpp(true)
            .cpp_link_stdlib(None)
            .out_dir(&out_dir)
            .pic(true)
            .compile_intermediates();

        let rust_ver = env.meta.semver.to_string();
        let llvm_ver = env.meta.llvm_version.as_ref().unwrap().major;
        let suffix = utils::dylib_suffix(&env.meta);
        let lib_llvm = format!("libLLVM-{llvm_ver}-rust-{rust_ver}.{suffix}");

        let lib_dir: PathBuf = path!(&env.rust_dev / "lib");
        let lib_llvm: PathBuf = path!(lib_dir / lib_llvm);

        if !lib_llvm.exists() {
            show_error!("Unable to locate LLVM within rust_dev artifacts ({lib_llvm:?}).")
        }

        let library_path = path!(out_dir / BSAN_PLUGIN);

        let cmd = cmd!(
            env.sh,
            "cc --shared {objects...} {lib_llvm} -o {library_path} -Wl,-rpath={lib_dir}"
        )
        .quiet();
        cmd.run()?;
        Ok(library_path)
    }

    fn install_llvm_pass(env: &mut BsanEnv) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let pass = Self::build_llvm_pass(env)?;
            env.copy_to_sysroot_libdir(&pass)
        })
    }

    fn build_runtime(env: &mut BsanEnv, flags: &[String], quiet: bool) -> Result<PathBuf> {
        env.with_rust_flags(RT_FLAGS, |env| env.build("bsan-rt", flags, quiet))?;
        let artifact = env.assert_artifact(BSAN_RT);
        let llvm_objcopy = env.target_binary("llvm-objcopy");
        cmd!(env.sh, "{llvm_objcopy} -w -G __bsan_*").arg(&artifact).quiet().run()?;
        Ok(artifact)
    }

    fn install_runtime(env: &mut BsanEnv, flags: &[String], quiet: bool) -> Result<()> {
        env.in_mode(Mode::Release, |env| {
            let runtime = Self::build_runtime(env, flags, quiet)?;
            env.copy_to_sysroot_libdir(&runtime)
        })
    }

    fn bin(env: &mut BsanEnv, name: String, flags: &[String]) -> Result<()> {
        let binary = env.target_binary(&name);
        let _ = cmd!(env.sh, "{binary} {flags...}").quiet().run();
        Ok(())
    }

    fn opt(env: &mut BsanEnv, args: &[String]) -> Result<()> {
        let pass = Self::build_llvm_pass(env)?;
        let pass = pass.to_str().unwrap();
        let opt = env.target_binary("opt");
        let _ =
            cmd!(env.sh, "{opt} --load-pass-plugin={pass} -passes=bsan {args...}").quiet().run();
        Ok(())
    }
}
