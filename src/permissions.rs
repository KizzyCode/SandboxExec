use super::{ Result, SandboxExecError, SANDBOX_EXEC_PERMISSIONS };
use std::env;


#[derive(Debug)]
pub enum Permission {
	AllowNetworkIn,
	AllowNetworkOut,
	AllowRead(String),
	AllowWrite(String)
}
impl Permission {
	pub fn from_key_value((key, value): (String, String)) -> Result<Self> {
		match key.as_ref() {
			"AllowNetwork" if value.to_lowercase() == "in" => Ok(Permission::AllowNetworkIn),
			"AllowNetwork" if value.to_lowercase() == "out" => Ok(Permission::AllowNetworkOut),
			"AllowRead" => Ok(Permission::AllowRead(value)),
			"AllowWrite" => Ok(Permission::AllowWrite(value)),
			
			key => throw_err!(SandboxExecError::ApiError, format!("Profile contains invalid key-value pair \"{}:{}\"", key, value))
		}
	}
}


fn parse_key_value(to_parse: String) -> Result<Vec<(String, String)>> {
	enum State{ Key(String), KeyValue(String, String) }
	
	let (mut key_value, mut state) = (Vec::new(), State::Key(String::new()));
	for c in to_parse.chars() {
		state = match state {
			State::Key(mut key) => if c == ':' { State::KeyValue(key, String::new()) }
				else { key.push(c); State::Key(key) },
			State::KeyValue(key, mut value) => if c == ',' { key_value.push((key, value)); State::Key(String::new()) }
				else { value.push(c); State::KeyValue(key, value) }
		}
	}
	match state {
		State::KeyValue(key, value) => key_value.push((key, value)),
		State::Key(key) => if !key.is_empty() { throw_err!(SandboxExecError::ApiError, format!("Profile contains incomplete key-value pair \"{}...\"", key)) }
	}
	
	Ok(key_value)
}


fn unescape_str(to_unescape: String) -> Result<String> {
	enum State{ Normal, Escaped(Vec<u8>) }
	
	fn from_hex(byte: u8) -> Result<u8> {
		Ok(match byte {
			b'0'...b'9' => byte - b'0',
			b'a'...b'f' => (byte - b'a') + 0xA,
			b'A'...b'F' => (byte - b'A') + 0xA,
			_ => throw_err!(SandboxExecError::ApiError, format!("Profile contains escape sequence with invalid byte \"0x{:02x}\"", byte))
		})
	}
	fn is_valid(c: u8) -> bool {
		match c {
			b'a'...b'z' | b'A'...b'Z' | b'0'...b'9' | b'.' | b'-' | b'_' | b'/' => true,
			_ => false
		}
	}
	
	let (mut unescaped, mut state) = (Vec::new(), State::Normal);
	for byte in to_unescape.bytes() {
		state = match state {
			State::Normal if byte == b'\\' => State::Escaped(Vec::new()),
			State::Normal if is_valid(byte) => { unescaped.push(byte); State::Normal },
			State::Normal => throw_err!(SandboxExecError::ApiError, format!("Profile contains invalid byte \"0x{:02x}\"", byte)),
			
			State::Escaped(ref seq) if seq.len() == 3 => {
				if seq[0] != b'x' { throw_err!(SandboxExecError::ApiError, format!("Profile contains escape sequence with invalid byte \"0x{:02x}\"", seq[0])) }
				unescaped.push((try_err!(from_hex(seq[1])) << 4) | try_err!(from_hex(seq[2])));
				State::Normal
			},
			State::Escaped(mut seq) => { seq.push(byte); State::Escaped(seq) }
		}
	}
	if let State::Escaped(_) = state { throw_err!(SandboxExecError::ApiError, "Profile contains incomplete escape sequence") }
	
	Ok(ok_or!(String::from_utf8(unescaped), throw_err!(SandboxExecError::ApiError, "Profile is not a valid UTF-8 string if unescaped")))
}


pub fn from_env() -> Result<Vec<Permission>> {
	let profile_string: String = ok_or!(env::var(SANDBOX_EXEC_PERMISSIONS), throw_err!(SandboxExecError::ApiError, "No valid profile specified"));
	
	let kv_pairs: Vec<(String, String)> = try_err!(parse_key_value(profile_string));
	
	let mut unescaped_kv_pairs = Vec::new();
	for (key, value) in kv_pairs {
		unescaped_kv_pairs.push((try_err!(unescape_str(key)), try_err!(unescape_str(value))));
	}
	
	let mut permissions = Vec::new();
	for key_value in unescaped_kv_pairs {
		permissions.push(try_err!(Permission::from_key_value(key_value)));
	}
	
	Ok(permissions)
}

