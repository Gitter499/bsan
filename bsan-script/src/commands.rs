use anyhow::Result;

use crate::utils::BsanEnv;
use crate::*;

static RT_FLAGS: &[&str] = &["-Cpanic=abort", "-Zpanic_abort_tests"];

impl Command {
    pub fn exec(self) -> Result<()> {
        let mut env = BsanEnv::new()?;
        match self {
            Command::Build { flags, quiet } => Self::build(&mut env, &flags, quiet),
            Command::Check { flags } => Self::check(&mut env, &flags),
            Command::Clippy { flags, check } => Self::clippy(&mut env, &flags, check),
            Command::Test { bless, flags } => Self::test(&mut env, &flags, bless),
            Command::Fmt { flags, check } => Self::fmt(&env, &flags, check),
            Command::Doc { flags } => Self::doc(&mut env, &flags),
            Command::Ci { flags, quiet } => Self::ci(&mut env, &flags, quiet),
        }
    }

    #[allow(dead_code)]
    fn install(_env: &mut BsanEnv) -> Result<()> {
        todo!()
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
        env.test(".", flags)?;
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
        env.build_llvm_pass()?;
        env.build(".", flags, false)?;
        env.with_rust_flags(RT_FLAGS, |env| env.build("bsan-rt", flags, quiet))
    }
}
