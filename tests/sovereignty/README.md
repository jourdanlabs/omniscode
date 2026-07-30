# Runtime sovereignty gate

`verify_runtime.py` builds a local `DYLD_INSERT_LIBRARIES` (macOS) or
`LD_PRELOAD` (Linux) interposer and runs both distributed executables through
the V1 offline command matrix.

It fails on any DNS, `AF_INET`, or `AF_INET6` attempt; on demo `AF_UNIX`
attempts; on synthetic operator or credential-state access; or on successful
and transient writes outside the exact Section 5.4 manifest. Every trace event
is bound to a PID and absolute process image. The no-argument PTY checks also
bind the client and temporary server to the exact sibling executables, require
instrumentation to survive the spawn, and permit only the controlled
`JCODE_SOCKET` Unix transport.

The credential read inventory is shared by the C interposer, its positive
control, and the Python verifier. Hostile provider/account environment values,
user keychains, auth files, update candidates, hooks, plugins, and executable
PATH entries must remain untouched.

Run after building both binaries:

```bash
python3 tests/sovereignty/verify_runtime.py \
  --jcode target/debug/jcode \
  --omnis-key target/debug/omnis-key
```

The retained JSON receipt defaults to
`target/sovereignty/runtime-receipt.json`.

Run the harness adversarial self-tests independently:

```bash
python3 tests/sovereignty/test_verify_runtime_adversarial.py
```
