SandboxExec
===========
Welcome to SandboxExec 🎉


What is SandboxExec?
--------------------
SandboxExec is a CLI-tool that allows you to execute other binaries in a sandbox.
It comes with the following profiles:
 - DenyDefault 
 - AllowReadWorkingDir
 - AllowWriteWorkingDir
 - AllowReadAll
 - AllowWriteAll	
 - AllowNetwork

How can I build SandboxExec?
----------------------------
Just clone the repository, change into the projects root directory and run `cargo build --release`.
You can find the resulting binary in `target/release`.

How do I use SandboxExec?
-------------------------
SandboxExec is configured using environment variables. There are two obligatory variables:
 - `SANDBOX_EXEC_BINARY`: The path to the binary to execute
 - `SANDBOX_EXEC_PROFILE`: A comma-separated string containing the sandbox profile-names
 
There is also a third environment-variable `SANDBOX_EXEC_DEBUG` which enables the debug mode if it
is defined.

All other environment variables and command line arguments are passed to the child.