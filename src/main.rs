#[macro_use] extern crate etrace;
use std::{ env, ffi::OsString, process::exit };


macro_rules! profile_add {
    ($($profile:expr),*) => ({
    	let mut num = 0u8;
    	$(num |= $profile as u8;)*
    	num
    });
}
macro_rules! profile_check {
    ($combined:expr, $profile:expr) => {
    	$combined & $profile as u8 == $profile as u8
    };
}


const SANDBOX_EXEC_BINARY: &str = "SANDBOX_EXEC_BINARY";
const SANDBOX_EXEC_PROFILE: &str = "SANDBOX_EXEC_PROFILE";
const SANDBOX_EXEC_DEBUG: &str = "SANDBOX_EXEC_DEBUG";


#[cfg(target_os = "macos")] #[path="sandbox_macos.rs"]
mod sandbox;
#[cfg(not(any(target_os = "macos")))] #[path="sandbox_fallback.rs"]
mod sandbox;


#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum SandboxExecError {
	ApiError = 1,
	SandboxError = 2,
	ExecError = 3,
	ChildError = 4,
}
pub type Result<T> = std::result::Result<T, etrace::Error<SandboxExecError>>;


#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum SandboxProfile {
	DenyDefault = 0b0_00_00,
	
	AllowReadWorkingDir = 0b0_00_01,
	AllowWriteWorkingDir = 0b0_00_10,
	
	AllowReadAll = 0b0_01_01,
	AllowWriteAll = 0b0_10_10,
	
	AllowNetwork = 0b1_00_00
}


fn main() {
	let debug = env::var_os(SANDBOX_EXEC_DEBUG).is_some();
	
    fn try_catch() -> Result<()> {
		let binary: OsString = some_or!(env::var_os(SANDBOX_EXEC_BINARY), throw_err!(SandboxExecError::ApiError, "No binary specified"));
		let profile = {
			let mut profile = SandboxProfile::DenyDefault as u8;
			
			let profile_string: String = ok_or!(env::var(SANDBOX_EXEC_PROFILE), throw_err!(SandboxExecError::ApiError, "No valid profile specified"));
			for profile_string in profile_string.split(',') {
				profile = profile_add!(profile, match profile_string {
					"DenyDefault" => SandboxProfile::DenyDefault,
					"AllowReadWorkingDir" => SandboxProfile::AllowReadWorkingDir,
					"AllowWriteWorkingDir" => SandboxProfile::AllowWriteWorkingDir,
					"AllowReadAll" => SandboxProfile::AllowReadAll,
					"AllowWriteAll" => SandboxProfile::AllowWriteAll,
					"AllowNetwork" => SandboxProfile::AllowNetwork,
					profile => throw_err!(SandboxExecError::ApiError, format!("Invalid profile \"{}\"", profile))
				})
			}
			profile
		};
		
		try_err!(sandbox::exec(binary, env::args_os().skip(1), profile));
		Ok(())
	}
	if let Err(error) = try_catch() {
		if debug { eprintln!("{}", error.to_string()) }
		exit(error.kind as i32);
	}
}
