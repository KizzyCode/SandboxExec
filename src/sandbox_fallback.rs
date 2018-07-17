use super::{ Result, SandboxExecError, Permission, SANDBOX_EXEC_BINARY, SANDBOX_EXEC_PERMISSIONS, SANDBOX_EXEC_DEBUG };
use std::{ ffi::OsString, process::{ Command, Child, ExitStatus } };


#[cfg(feature="opportunistic")]
pub fn exec(binary: OsString, args: impl Iterator<Item = OsString>, _permissions: &[Permission]) -> Result<()> {
	let exit_status: ExitStatus = {
		let mut command = Command::new(binary);
		command.args(args);
		command.env_remove(SANDBOX_EXEC_BINARY).env_remove(SANDBOX_EXEC_PERMISSIONS).env_remove(SANDBOX_EXEC_DEBUG);
		ok_or!(command.status(), throw_err!(SandboxExecError::ExecError, "Failed to execute child"))
	};
	if !exit_status.success() {
		let code = exit_status.code().and_then(|c| Some(c.to_string())).unwrap_or("?".to_string());
		throw_err!(SandboxExecError::ChildError, format!("Child failed with code {}", code))
	}
	Ok(())
}


#[cfg(not(feature="opportunistic"))]
pub fn exec(_binary: OsString, _args: impl Iterator<Item = OsString>, _permissions: &[Permission]) -> Result<()> {
	throw_err!(SandboxExecError::SandboxError, "No supported sandbox mechanism for this platform")
}