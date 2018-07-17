use super::{ Result, SandboxExecError, Permission, SANDBOX_EXEC_BINARY, SANDBOX_EXEC_PERMISSIONS, SANDBOX_EXEC_DEBUG };
use std::{ ffi::{ OsStr, OsString }, path::{ Path, PathBuf }, os::unix::ffi::OsStrExt, process::{ Command, ExitStatus } };


pub fn build_profile(binary: &OsStr, permissions: &[Permission]) -> Result<String> {
	fn escape_path(path: impl AsRef<Path>) -> Result<String> {
		let path: PathBuf = ok_or!(path.as_ref().canonicalize(), throw_err!(SandboxExecError::SandboxError, "Failed to canonicalize path"));
		
		let mut escaped = if path.is_dir() { "(subpath \"".to_string() }
				else { "(literal \"".to_string() };
		path.as_os_str().as_bytes().iter().for_each(|byte| match byte {
			b'a'...b'z' | b'A'...b'Z' | b'0'...b'9' | b' ' | b'.' | b'-' | b'_' | b'/' => escaped.push(*byte as char),
			byte => escaped.push_str(&format!("\\x{:02x}", byte))
		});
		escaped.push_str("\")");
		
		Ok(escaped)
	}
	
	// Skeleton
	let mut profile_string = String::new();
	profile_string.push_str("(version 1)\n");
	profile_string.push_str("(deny default)\n\n");
	profile_string.push_str("(import \"/System/Library/Sandbox/Profiles/bsd.sb\")\n");
	
	// Allow mach-service-lookup and read/write to temporary directories
	profile_string.push_str("(allow mach-lookup)\n\n");
	profile_string.push_str("(allow file-read* file-write*\n");
	profile_string.push_str("\t(regex #\"^(/private)?/var/folders/[^/]+/[^/]+/C($|/)\")\n");
	profile_string.push_str("\t(regex #\"^(/private)?/var/folders/[^/]+/[^/]+/T($|/)\"))\n\n");
	
	// Allow loading shared libraries
	profile_string.push_str("(allow file-read*\n");
	profile_string.push_str("\t(subpath \"/usr/local/lib/\")\n");
	profile_string.push_str("\t(regex #\"^/usr/local/opt/[^/]*/lib/\")\n");
	profile_string.push_str("\t(regex #\"^/usr/local/Cellar/[^/]*/[^/]*/lib/\"))\n\n");
	
	// Allow execution of the binary
	profile_string.push_str("(allow process-exec\n");
	profile_string.push_str(&format!("\t{})\n\n", try_err!(escape_path(binary))));
	
	// Add permissions
	for permission in permissions {
		match permission {
			Permission::AllowNetworkIn => profile_string.push_str("(allow network-bind network-inbound)\n\n"),
			Permission::AllowNetworkOut => profile_string.push_str("(allow network-outbound)\n\n"),
			Permission::AllowRead(path) => {
				profile_string.push_str("(allow file-read*\n");
				profile_string.push_str(&format!("\t{})\n\n", try_err!(escape_path(path))));
			},
			Permission::AllowWrite(path) => {
				profile_string.push_str("(allow file-write*\n");
				profile_string.push_str(&format!("\t{})\n\n", try_err!(escape_path(path))));
			}
		}
	}
	
	Ok(profile_string)
}


pub fn exec(binary: OsString, args: impl Iterator<Item = OsString>, permissions: &[Permission]) -> Result<()> {
	let exit_status: ExitStatus = {
		let mut command = Command::new("/usr/bin/sandbox-exec");
		command.arg("-p").arg(try_err!(build_profile(&binary, permissions))).arg(binary).args(args);
		command.env_remove(SANDBOX_EXEC_BINARY).env_remove(SANDBOX_EXEC_PERMISSIONS).env_remove(SANDBOX_EXEC_DEBUG);
		ok_or!(command.status(), throw_err!(SandboxExecError::ExecError, "Failed to execute child"))
	};
	if !exit_status.success() {
		let code = exit_status.code().and_then(|c| Some(c.to_string())).unwrap_or("?".to_string());
		throw_err!(SandboxExecError::ChildError, format!("Child failed with code {}", code))
	}
	Ok(())
}
