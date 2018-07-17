#[macro_use] extern crate etrace;

mod permissions;
#[cfg(target_os = "macos")] #[path="sandbox_macos.rs"]
mod sandbox;
#[cfg(not(any(target_os = "macos")))] #[path="sandbox_fallback.rs"]
mod sandbox;

use std::{ env, ffi::OsString, process::exit };
use self::permissions::Permission;


const SANDBOX_EXEC_BINARY: &str = "SANDBOX_EXEC_BINARY";
const SANDBOX_EXEC_PERMISSIONS: &str = "SANDBOX_EXEC_PERMISSIONS";
const SANDBOX_EXEC_DEBUG: &str = "SANDBOX_EXEC_DEBUG";


#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum SandboxExecError {
	ApiError = 1,
	SandboxError = 2,
	ExecError = 3,
	ChildError = 4,
}
pub type Result<T> = std::result::Result<T, etrace::Error<SandboxExecError>>;


fn main() {
    fn try_catch() -> Result<()> {
		let binary: OsString = some_or!(env::var_os(SANDBOX_EXEC_BINARY), throw_err!(SandboxExecError::ApiError, "No binary specified"));
		let permissions: Vec<Permission> = try_err!(permissions::from_env());
		try_err!(sandbox::exec(binary, env::args_os().skip(1), &permissions));
		Ok(())
	}
	if let Err(error) = try_catch() {
		if env::var_os(SANDBOX_EXEC_DEBUG).is_some() { eprintln!("{}", error.to_string()) }
		exit(error.kind as i32);
	}
}
