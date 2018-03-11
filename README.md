Requirements
------------
capstone

Examples
--------

- `invoke_exported_function`: attach to a running process (see `target`) and invoke one of its exported functions
- `replace_call`: replace `puts` call with a custom function by exploting the GOT table

Notes
-----
ptrace attaches to a specific thread ID. The other threads will continue to run
normally unless you ptrace to all of them (see `pbridge_attach_all`).
