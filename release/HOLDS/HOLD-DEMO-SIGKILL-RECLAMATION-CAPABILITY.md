# HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY

Status: `HOLD`

Owner: Captain/specification amendment plus independent review

Builder verdict: none

The frozen specification simultaneously requires:

- `demo integrity` to access and write only one private temporary root that it
  creates for the current run;
- the next run never to discover, enumerate, open, or hash any other plausible
  demo or operator-state root; and
- every uncatchable-crash remnant to be safely reclaimable on the next run.

Those requirements leave no authenticated capability by which the next
process can distinguish its predecessor's remnant from a same-UID plausible
preplant. A capability written inside the root cannot be read without first
accessing a path the next run is forbidden to access. A capability written
outside the root violates the one-root write boundary. Writing it after
`mkdir` also leaves the demonstrated `mkdir`-to-capability `SIGKILL` gap;
writing it before `mkdir` leaves an external artifact and still violates the
boundary. PID, name grammar, mode, ownership, inode, timestamps, lock state,
and marker contents are not unforgeable authority.

The candidate therefore preserves plausible preplants and does not scan or
reclaim prior roots. Normal exit, unwind, and catchable signals remain
separately testable requirements; they are not waived by this HOLD.

Reproduce after building `omnis-key`:

```bash
cargo build --locked -p omnis-key-cli --bin omnis-key
python3 tests/holds/reproduce_demo_sigkill_reclamation_hold.py \
  --omnis-key target/debug/omnis-key
```

The fixture uses an external interposer to deliver `SIGKILL` immediately after
the demo's successful root `mkdir`, verifies the remnant is an empty private
`0700` directory, creates exact-grammar empty/sentinel/symlink preplants, runs
the demo again, and requires this marker:

```text
HOLD_REPRODUCED: HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY killedRootPrivate=true nextRunReclaimed=false plausiblePreplantsPreserved=true
```

It removes only the exact fixture entries it created. Resolving this HOLD
requires an explicit specification change that grants a safe capability
location or narrows the next-run reclamation requirement. The builder does
not waive the P0 and does not issue `CLEAR`.
