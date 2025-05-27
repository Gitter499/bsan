use std::fs;

use anyhow::Result;
use path_macro::path;
use xshell::cmd;

use crate::env::BsanEnv;
use crate::utils::show_error;
use crate::*;

static RT_FLAGS: &[&str] = &["-Cpanic=abort", "-Zpanic_abort_tests"];

impl Command {
    pub fn exec(self) -> Result<()> {
        let mut env = BsanEnv::new()?;
        match self {
            Command::Setup => Ok(()),
            Command::Build { flags, quiet } => Self::build(&mut env, &flags, quiet),
            Command::Check { flags } => Self::check(&mut env, &flags),
            Command::Clippy { flags, check } => Self::clippy(&mut env, &flags, check),
            Command::Test { bless, flags } => Self::test(&mut env, &flags, bless),
            Command::Fmt { flags, check } => Self::fmt(&env, &flags, check),
            Command::Doc { flags } => Self::doc(&mut env, &flags),
            Command::Ci { flags, quiet } => Self::ci(&mut env, &flags, quiet),
            Command::Bin { binary_name, args } => Self::bin(&mut env, binary_name, args),
            Command::Opt { args } => Self::opt(&mut env, args),
            Command::Install { args } => Self::install(&mut env, args),
        }
    }

    #[allow(dead_code)]
    fn install(env: &mut BsanEnv, args: Vec<String>) -> Result<()> {
        env.install("cargo-bsan", ".", &args)?;
        env.install("bsan-driver", ".", args)?;
        Self::install_llvm_pass(env)
    }

    fn ci(env: &mut BsanEnv, flags: &[String], quiet: bool) -> Result<()> {
        Self::fmt(env, flags, true)?;
        Self::clippy(env, flags, true)?;
        Self::build(env, flags, quiet)?;
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
        env.with_rust_flags(RT_FLAGS, |env| env.test("bsan-rt", flags))
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

    fn build(env: &mut BsanEnv, flags: &[String], quiet: bool) -> Result<()> {
        Self::build_llvm_pass(env, false)?;
        env.build(".", flags, false)?;
        env.with_rust_flags(RT_FLAGS, |env| env.build("bsan-rt", flags, quiet))
    }

    pub fn install_llvm_pass(env: &mut BsanEnv) -> Result<()> {
        let pass = Self::build_llvm_pass(env, true)?;
        let pass_name = pass.file_name().unwrap();
        let sysroot = path!(env.sysroot / "lib" / pass_name);
        fs::copy(pass, sysroot)?;
        Ok(())
    }

    pub fn build_llvm_pass(env: &mut BsanEnv, opt: bool) -> Result<PathBuf> {
        let cxxflags = env.llvm_config().arg("--cxxflags").output()?.stdout;

        let mut cfg = env.cc();
        cfg.warnings(false);

        for flag in String::from_utf8(cxxflags)?.split_whitespace() {
            cfg.flag(flag);
        }

        let out_dir = path!(&env.root_dir / "target" / "bsan_pass");
        if out_dir.exists() {
            fs::remove_dir_all(&out_dir)?;
        }
        fs::create_dir_all(&out_dir)?;

        let src_dir = path!(&env.root_dir / "bsan-pass");

        let opt_level = if opt { 3 } else { 0 };
        let objects = cfg
            .file(path!(src_dir / "BorrowSanitizer.cpp"))
            .include(src_dir)
            .opt_level(opt_level)
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

        let library_name = format!("libbsan.{}", utils::dylib_suffix(&env.meta));
        let library_path = path!(out_dir / library_name);
        let cmd = cmd!(
            env.sh,
            "cc --shared {objects...} {lib_llvm} -o {library_path} -Wl,-rpath={lib_dir}"
        )
        .quiet();
        cmd.run()?;
        Ok(library_path)
    }

    fn bin(env: &mut BsanEnv, name: String, flags: Vec<String>) -> Result<()> {
        let binary = env.target_binary(&name);
        let _ = cmd!(env.sh, "{binary} {flags...}").quiet().run();
        Ok(())
    }

    fn opt(env: &mut BsanEnv, args: Vec<String>) -> Result<()> {
        let pass = Self::build_llvm_pass(env, false)?;
        let pass = pass.to_str().unwrap();
        let opt = env.target_binary("opt");
        let _ =
            cmd!(env.sh, "{opt} --load-pass-plugin={pass} -passes=bsan {args...}").quiet().run();
        Ok(())
    }
}
