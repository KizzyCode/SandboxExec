use super::{ Result, SandboxExecError, SandboxProfile, SANDBOX_EXEC_BINARY, SANDBOX_EXEC_PROFILE, SANDBOX_EXEC_DEBUG };
use std::{ ffi::{ OsStr, OsString }, os::unix::ffi::OsStrExt, env, process::{ Command, ExitStatus } };


pub fn build_profile(binary: &OsStr, profile: u8) -> String {
	fn escape_str(string: &OsStr) -> String {
		let mut escaped = String::new();
		string.as_bytes().iter().for_each(|byte| match byte {
			b'a'...b'z' | b'A'...b'Z' | b'0'...b'9' | b' ' | b'.' | b'-' | b'_' | b'/' => escaped.push(*byte as char),
			byte => escaped.push_str(&format!("\\x{:02x}", byte))
		});
		escaped
	}
	
	// Skeleton
	let mut profile_string = String::new();
	profile_string.push_str("(version 1)\n");
	profile_string.push_str("(deny default)\n\n");
	profile_string.push_str("(import \"/System/Library/Sandbox/Profiles/system.sb\")\n\n");
	
	// Allow execution of binary
	profile_string.push_str("(allow process-exec\n");
	profile_string.push_str(&format!("\t(literal \"{}\"))\n\n", escape_str(binary)));
	
	// Read/write working dir
	if let Some(working_dir) = env::current_dir().ok().and_then(|p| Some(escape_str(p.as_os_str()))) {
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
	
	profile_string
}


pub fn exec(binary: OsString, args: impl Iterator<Item = OsString>, profile: u8) -> Result<()> {
	let args = {
		let mut combined_args: Vec<OsString> = vec!["-p".into(), build_profile(&binary, profile).into(), binary];
		combined_args.extend(args);
		combined_args
	};
	
	let exit_status: ExitStatus = {
		let mut command = Command::new("/usr/bin/sandbox-exec");
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
