# pbridge

pbridge is a framework which provides an API to ease linux process debugging and
function hijacking via the `ptrace` environment.

Here is a list of something you can do with this framework:

- Resolve static and runtime symbols adresses of a running process
- Programmatically attach breakpoints on a running process functions
- Inject custom code and data into a new mmapped region in process memory and execute it
- Call functions located into an exernal process as "blackbox" with your own supplied data
- Replace calls to the standard library with your custom functions

This is currently limited to a 64 bits linux OS.

Compiling
---------

Base `gcc` and `make` environment required.
The `capstone` library is required to perform code disassembly for debugging.

In order to build the `libpbridge.a` library and the examples, just run `make`.

Examples
--------

The following examples (sometimes also used as test cases) are provided:

- `invoke_exported_function`: attach to a running process (run `target`) and invoke one of its exported functions
- `replace_call`: replace `puts` call with a custom function by exploting the GOT table
- `breakpoint_test`: place breakpoints on process memory and wait for them to trigger

I assume that the tracee process (the one you run to attach to the target process) has
root privileges. Otherwise you should deal with [Yama](https://www.kernel.org/doc/Documentation/security/Yama.txt).

API Documentation
-----------------

See `pbridge.h` and `utils.h` for a list of API functions. The examples show how
to use this API to solve specific tasks. The API is subject to change.

References
----------

- [ptrace-call-userspace](https://github.com/eklitzke/ptrace-call-userspace) for
  primitives using ptrace API

- [Calling Conventions](https://wiki.osdev.org/Calling_Conventions)

- [PLT and GOT](https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html)

- [The Art Of Symbol Resolution](https://0x00sec.org/t/linux-internals-the-art-of-symbol-resolution/1488)

Notes
-----
- ptrace attaches to a specific thread ID. The other threads will continue to run
  normally unless you ptrace to all of them (see `pbridge_attach_all`).

- it is very important to understand when we are dealing with the tracee (current
  process) memory addresses and when we are dealing with the traced (attached
  process) addresses.
