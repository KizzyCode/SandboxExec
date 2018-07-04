use super::{ Result, SandboxExecError, SandboxProfile, SANDBOX_EXEC_BINARY, SANDBOX_EXEC_PROFILE, SANDBOX_EXEC_DEBUG };
use std::{ ffi::OsString, process::{ Command, Child, ExitStatus } };


#[cfg(feature="opportunistic")]
pub fn exec(binary: OsString, args: impl Iterator<Item = OsString>, profile: u8) -> Result<()> {
	let exit_status: ExitStatus = {
		let mut command = Command::new(binary);
		command.args(args);
		command.env_remove(SANDBOX_EXEC_BINARY);
		command.env_remove(SANDBOX_EXEC_PROFILE);
		command.env_remove(SANDBOX_EXEC_DEBUG);
		ok_or!(command.status(), throw_err!(SandboxExecError::ExecError, "Failed to execute child"))
	};
	if !exit_status.success() {
		let code = exit_status.code().and_then(|c| Some(c.to_string())).unwrap_or("?".to_string());
		throw_err!(SandboxExecError::ChildError, format!("Child failed with code {}", code))
	}
	Ok(())
}


#[cfg(not(feature="opportunistic"))]
pub fn exec(_binary: OsString, _args: impl Iterator<Item = OsString>, _profile: u8) -> Result<()> {
	throw_err!(SandboxExecError::SandboxError, "No supported sandbox mechanism for this platform")
}