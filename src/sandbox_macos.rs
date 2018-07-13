use super::{ Result, SandboxExecError, SandboxProfile, SANDBOX_EXEC_BINARY, SANDBOX_EXEC_PROFILE, SANDBOX_EXEC_DEBUG };
use std::{ ffi::{ OsStr, OsString }, path::{ Path, PathBuf }, os::unix::ffi::OsStrExt, env, process::{ Command, ExitStatus } };


pub fn build_profile(binary: &OsStr, profile: u8) -> Result<String> {
	fn escape_path(path: impl AsRef<Path>) -> Result<String> {
		let (path, mut escaped): (PathBuf, String) = (
			ok_or!(path.as_ref().canonicalize(), throw_err!(SandboxExecError::SandboxError, "Failed to canonicalize path")),
			String::new()
		);
		path.as_os_str().as_bytes().iter().for_each(|byte| match byte {
			b'a'...b'z' | b'A'...b'Z' | b'0'...b'9' | b' ' | b'.' | b'-' | b'_' | b'/' => escaped.push(*byte as char),
			byte => escaped.push_str(&format!("\\x{:02x}", byte))
		});
		Ok(escaped)
	}
	
	// Canonicalize and escape path
	let binary: String = try_err!(escape_path(binary));
	let working_dir: Option<String> = {
		if let Ok(current_dir) = env::current_dir() { Some(try_err!(escape_path(current_dir.as_os_str()))) }
			else { None }
	};
	
	// Skeleton
	let mut profile_string = String::new();
	profile_string.push_str("(version 1)\n");
	profile_string.push_str("(deny default)\n\n");
	profile_string.push_str("(import \"/System/Library/Sandbox/Profiles/system.sb\")\n\n");
	
	// Allow execution of binary
	profile_string.push_str("(allow process-exec\n");
	profile_string.push_str(&format!("\t(literal \"{}\"))\n\n", binary));
	
	// Read/write working dir
	if let Some(working_dir) = working_dir {
		if profile_check!(profile, SandboxProfile::AllowReadWorkingDir) {
			profile_string.push_str("(allow file-read*\n");
			profile_string.push_str(&format!("\t(subpath \"{}\"))\n\n", working_dir));
		}
		if profile_check!(profile, SandboxProfile::AllowWriteWorkingDir) {
			profile_string.push_str("(allow file-write*\n");
			profile_string.push_str(&format!("\t(subpath \"{}\"))\n\n", working_dir));
		}
	}
	
	// Read/write global
	if profile_check!(profile, SandboxProfile::AllowReadAll) {
		profile_string.push_str("(allow file-read*\n");
		profile_string.push_str(&format!("\t(subpath \"/\"))\n\n"));
	}
	if profile_check!(profile, SandboxProfile::AllowWriteAll) {
		profile_string.push_str("(allow file-write*\n");
		profile_string.push_str(&format!("\t(subpath \"/\"))\n\n"));
	}
	
	// Allow network
	if profile_check!(profile, SandboxProfile::AllowNetwork)  {
		profile_string.push_str("(allow network*)\n\n")
	}
	
	Ok(profile_string)
}


pub fn exec(binary: OsString, args: impl Iterator<Item = OsString>, profile: u8) -> Result<()> {
	let exit_status: ExitStatus = {
		let mut command = Command::new("/usr/bin/sandbox-exec");
		command.arg("-p").arg(try_err!(build_profile(&binary, profile))).arg(binary).args(args);
		command.env_remove(SANDBOX_EXEC_BINARY).env_remove(SANDBOX_EXEC_PROFILE).env_remove(SANDBOX_EXEC_DEBUG);
		ok_or!(command.status(), throw_err!(SandboxExecError::ExecError, "Failed to execute child"))
	};
	if !exit_status.success() {
		let code = exit_status.code().and_then(|c| Some(c.to_string())).unwrap_or("?".to_string());
		throw_err!(SandboxExecError::ChildError, format!("Child failed with code {}", code))
	}
	Ok(())
}
