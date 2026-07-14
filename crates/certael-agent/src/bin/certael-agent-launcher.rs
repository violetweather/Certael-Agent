use anyhow::{bail, Context, Result};
use certael_agent_updater::active_target;
use std::process::Command;

fn main() -> Result<()> {
    let launcher = std::env::current_exe()
        .context("cannot locate the Certael Agent launcher")?
        .canonicalize()
        .context("cannot resolve the Certael Agent launcher")?;
    let install_root = launcher
        .parent()
        .context("Certael Agent launcher has no installation root")?;
    let target = active_target(install_root)
        .context("the active Certael Agent installation is invalid; run recovery or reinstall")?;
    if target == launcher {
        bail!("Certael Agent launcher activation loop detected");
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = Command::new(target)
            .args(std::env::args_os().skip(1))
            .exec();
        Err(error).context("failed to execute the active Certael Agent")
    }
    #[cfg(windows)]
    {
        let status = Command::new(target)
            .args(std::env::args_os().skip(1))
            .status()
            .context("failed to execute the active Certael Agent")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}
