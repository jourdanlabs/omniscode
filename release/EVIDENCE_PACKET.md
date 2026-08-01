# Builder evidence packet

`scripts/assemble_verification_index.py` derives the verification index from
retained raw receipts. `scripts/generate_builder_manifest.py` then creates an
unauthenticated local builder packet from that index. Neither tool issues
`CLEAR`, creates a tag, or performs an external action.

Keep the assembly plan, raw command receipts, copied rich runtime receipts,
and one full security-preflight report per passed platform under one private
packet directory. Run the assembler first:

```text
scripts/assemble_verification_index.py \
  --repo <clean-fresh-clone> \
  --ref <candidate-commit> \
  --plan <packet>/verification-plan.json \
  --archive <packet>/source.tar.gz \
  --security-report linux=<packet>/linux-security-report.json \
  --security-report macos=<packet>/macos-security-report.json \
  --output <packet>/verification-index.json
```

The plan and its parent directory must not be symlinks. The plan, raw command
receipts, clone-provenance markers, rich runtime receipts, security reports,
and security-report digest sidecars must grant no group or other access. The
assembler refuses to overwrite its output.

The plan is intentionally not a place for builder conclusions. It has exactly
this shape:

```json
{
  "schemaVersion": 1,
  "candidate": {
    "commit": "exact commit",
    "tree": "exact tree"
  },
  "externalActions": false,
  "receiptPaths": [
    "receipts/linux-section9-01-fmt.txt"
  ],
  "runtimeEvidence": [
    {
      "platform": "linux",
      "receiptId": "linux-additional-sovereignty-runtime",
      "path": "receipts/linux-runtime-sovereignty.json"
    }
  ],
  "platforms": [
    {
      "name": "linux",
      "status": "PASS",
      "cloneCreationReceiptId": "linux-fresh-clone-created",
      "cloneVerificationReceiptId": "linux-setup-clone-verification",
      "cloneMarkerPath": "receipts/linux-fresh-clone-marker.json",
      "toolchainReceiptId": "linux-toolchain"
    },
    {
      "name": "macos",
      "status": "HOLD",
      "holdId": "MACOS_FRESH_CLONE_PENDING"
    }
  ],
  "caseHolds": {
    "reordered_receipt_refusal": "REORDERED_RECEIPT_FIXTURE_PENDING"
  },
  "additionalHolds": [
    {
      "id": "MACOS_FRESH_CLONE_PENDING",
      "description": "A macOS fresh-clone receipt is not yet retained.",
      "owner": "builder",
      "receiptIds": []
    },
    {
      "id": "REORDERED_RECEIPT_FIXTURE_PENDING",
      "description": "The retained receipt suite has no exact reorder fixture.",
      "owner": "builder",
      "receiptIds": ["linux-section9-08-test-base-omnis"]
    }
  ]
}
```

The plan may name evidence and named HOLDs. It cannot supply command status,
exit status, digest, toolchain text, version values, PASS mappings, a verdict,
authentication, or `CLEAR`. Unknown plan keys and gate-assertion keys are
rejected.

Create raw receipts with the tracked runner. Keep `PACKET/receipts` outside
the fresh clone so evidence creation cannot dirty the candidate:

```bash
export OMNIS_BUILDER_SUPPLEMENTAL_TOOL_PATH=<canonical-scanner-bin>:<canonical-go-bin>
scripts/run_builder_receipt.sh \
  <clean-fresh-clone> linux <unique-id> \
  <packet>/receipts/<unique-id>.txt \
  '<exact command>'
```

Use the same explicit supplemental path for every receipt on one platform.
The runner ignores caller `PATH`, resolves the platform Git, Cargo, Rust,
Python, C compiler, Bash, and Rust components from fixed absolute locations,
and shadows those names in a private tool directory. It executes direct argv
without `bash -c`. Each receipt binds every resolved executable path,
SHA-256, version/build identity, the canonical supplemental path, and one
fingerprint over that exact set. When the supplemental path is present, it
must resolve exactly one regular `gitleaks`, `cargo-audit`, `cargo-deny`, and
`go`; their absolute paths, hashes, and identities are bound too and only
private links to those exact files enter command `PATH`. Supplemental
directories cannot replace a core tool; the security preflight separately
validates the pinned scanner hashes.

The runner uses that same absolute Git for cleanliness, commit/tree identity,
and command execution. It refuses a dirty worktree or host/platform mismatch,
retains combined output and the real exit status, publishes with mode `0600`,
and propagates command failure. The assembler rejects legacy or malformed
receipt framing, nonzero listed receipts, forged candidate identity,
duplicate IDs/commands, unsafe paths, recomputed digest mismatches, and any
platform whose receipts do not share one exact toolchain fingerprint.

Create and verify each platform clone with the tracked local-only orchestrator:

```bash
scripts/prepare_builder_platform_suite.sh \
  <clean-full-source-repo> linux \
  <private-work-root>/linux-fresh-clone \
  <packet>/receipts
```

The source repository must itself be clean, non-shallow, non-partial, and free
of promisor, filter, alternates, graft, and replacement-ref state. The
orchestrator invokes `git clone --no-local --no-hardlinks --no-checkout` with
only the local `file` protocol permitted and ambient Git configuration
disabled. It retains a creation receipt and private canonical marker, checks
out the exact candidate as detached `HEAD`, then runs the in-clone verifier
and platform suite. No network protocol or external action is permitted.

To rerun only the command suite inside an already created clone:

```bash
scripts/run_builder_platform_suite.sh \
  <fresh-clone> linux <packet>/receipts \
  <packet>/receipts/linux-fresh-clone-marker.json
```

Run the preparation wrapper independently on Linux and macOS. The suite copies
the rich runtime JSON next to the raw receipts after the runtime verifier
passes. The security-preflight fault matrix remains a separate receipt because
it requires the retained archive, pinned advisory database, and pinned tools.

For each passed platform, retain exactly one raw receipt for every Section 9
command, both canonical version commands, the `jcode` build, the runtime
sovereignty verifier, workspace-metadata checker, third-party-inventory
checker, release-hygiene checker, canonical-boundary tests, exhaustive
workspace tests, exact release-diff guardrail, whitespace-diff check,
dependency-boundary check, and assembler self-tests. The additional exact
commands are:

```bash
cargo test -p jcode-base omnis::boundary::tests
cargo test --workspace --all-targets --locked
python3 scripts/check_release_diff_guardrails.py --base 670955adf1eebb207bc4a4411e5f6083562d167c --candidate HEAD --check-warnings
git diff --check
git diff --check 670955adf1eebb207bc4a4411e5f6083562d167c..HEAD
python3 scripts/check_dependency_boundaries.py
python3 scripts/test_assemble_verification_index.py
python3 scripts/test_verify_source_archive.py
python3 scripts/test_security_exception_binding.py
python3 tests/sovereignty/test_verify_runtime_adversarial.py
python3 tests/holds/reproduce_demo_sigkill_reclamation_hold.py \
  --omnis-key target/debug/omnis-key
```

Also retain this exact toolchain receipt:

```bash
uname -a && rustc -Vv && cargo -V && git --version && python3 --version && cc --version
```

The assembler parses it into `uname`, Rust release/host, Cargo, Git, Python,
and C-compiler identity; plan-authored toolchain strings are not accepted.

The fresh-clone case cannot be satisfied by an in-clone cleanliness command
alone. For each passed platform the assembler requires exactly one creation
receipt, one in-clone verification receipt, and their shared marker. Both raw
receipts bind the exact candidate commit/tree and identical marker SHA-256.
The marker and verifier independently require detached exact `HEAD`, a clean
worktree, `--is-shallow-repository=false`, no shallow file, no
`extensions.partialClone`, no `remote.*.promisor`, no
`remote.*.partialclonefilter`, no alternates/grafts/replacement refs, and a
successful strict connectivity check.

Run the complete pinned security preflight independently on each passed
platform and retain its report and exact `.sha256` sidecar:

```bash
scripts/security_preflight.sh \
  --archive <packet>/source.tar.gz \
  --report <packet>/linux-security-report.json \
  --advisory-db <pinned-advisory-db>
```

Use a distinct `macos-security-report.json` on macOS. The assembler binds each
report to its platform-specific pinned scanner target, exact candidate/tree,
archive identity, advisory HOLDs, digest, and sidecar; report platforms must
exactly equal passed fresh-clone platforms.

Retain the preflight itself through the command runner using the canonical
absolute-path grammar:

```bash
scripts/run_builder_receipt.sh \
  <clean-fresh-clone> linux linux-security-preflight \
  <packet>/receipts/linux-security-preflight.txt \
  'scripts/security_preflight.sh --archive <absolute-archive> --report <absolute-report> --advisory-db <absolute-advisory-db>'
```

The assembler requires exactly one such receipt per passed platform and binds
its stdout commit, tree, and report digest through
`assembly.securityReports[].commandReceiptId`.

Security fault evidence uses this frozen argument grammar, with the three
paths shell-quoted when needed:

```bash
tests/security/verify_preflight_faults.sh --archive PATH --advisory-db PATH --tools-dir PATH
```

It must emit `PASS: security preflight failed closed for 11 injected faults`.
The canonical boundary case additionally requires:

```bash
cargo test -p jcode-base omnis::boundary::tests
```

The assembler parses retained Cargo status lines for every exact semantic test
marker in `CASE_GROUPS` in `scripts/assemble_verification_index.py`. A marker
counts only when a line has `test <qualified-name> ... ok`; a diagnostic
substring, `ignored`, skipped, or failed test cannot satisfy a case. In
particular, it will not treat a checkpoint-record reorder test as a
receipt-ledger reorder test. The expected receipt-ledger markers
`partial_byte_and_mid_record_truncation_are_refused_without_reseed`,
`valid_prefix_tail_removal_remains_locally_undetected_without_checkpoint`, and
`reordered_receipts_are_refused` must all be present in the exact base OMNIS
test receipt or the corresponding case remains a named HOLD.

Canonical boundary PASS additionally requires both
`concrete_wrong_owned_ledger_is_refused_without_mutation` and
`concrete_extended_acl_is_refused` to finish with exact `... ok` status.

The rich runtime JSON is validated independently of the raw command wrapper.
Its digest must be the digest printed by the matching runtime command receipt;
it must bind a clean exact commit/tree, successful instrumentation positive
controls, all advertised binary cases, zero DNS/Internet/operator attempts,
demo fixture preservation, exact write manifests, and hostile credential-free
PTY startup/shutdown proofs.

The assembler always records these external conditions as named HOLDs:

- the frozen demo SIGKILL-reclamation capability contradiction;
- proposed RustSec exceptions pending independent review;
- hosted CI not run under the builder's no-push boundary;
- exact GitHub-generated tag archive unavailable;
- signed RC and authenticated manifest not created;
- hosted settings receipt not captured; and
- independent cold gates pending.

The first item is the implementation HOLD documented and reproduced by
`release/HOLDS/HOLD-DEMO-SIGKILL-RECLAMATION-CAPABILITY.md`. It maps the
`offline_fixture_demo` adversarial case to a HOLD even when the credential-free
happy path passes. This does not waive normal, unwind, or catchable-signal
cleanup. The builder records the contradiction and issues no gate verdict.

The triggered-workflow case therefore maps to
`HOSTED_CI_NOT_RUN_CAPTAIN_CONTROLLED`, and the exact GitHub archive case maps
to `GITHUB_GENERATED_TAG_ARCHIVE_NOT_AVAILABLE`. A local archive cannot be
substituted for either hosted condition. Informational RustSec warnings add a
separate remediation HOLD.

After assembly, generate the builder manifest:

```text
scripts/generate_builder_manifest.py \
  --ref <candidate-commit> \
  --archive <source.tar.gz> \
  --security-report linux=<linux-security-report.json> \
  --security-report macos=<macos-security-report.json> \
  --verification-index <verification-index.json> \
  --output <builder-manifest.json>
```

The derived verification index is JSON with `schemaVersion: 1`, the exact
`candidate.commit` and `candidate.tree`, `externalActions: false`, and one of:

- `VERIFICATION_COMPLETE` with an empty `knownHolds` array; or
- `VERIFICATION_COMPLETE_WITH_NAMED_HOLDS`, where every incomplete
  adversarial/platform case points to a structured, named `HOLD`.

When the exact proposed-exception set is nonempty, the assembler includes
`RUSTSEC_PROPOSED_EXCEPTIONS_PENDING_INDEPENDENT_REVIEW` as a named HOLD and
the security report labels the scoped expiring proposals
`PENDING_INDEPENDENT_REVIEW`; they are not builder-approved exceptions. When
the set is empty, the unsuppressed audit must exit zero with an exactly empty
vulnerability list, and that proposal HOLD must be absent.
When the pinned scan reports any informational advisory, the builder must also
include `RUSTSEC_INFORMATIONAL_WARNINGS_PENDING_REMEDIATION`. The retained
security report binds every warning's advisory ID, package, and version; the
builder does not call that set clean.

`section9` contains receipts for every exact command in Section 9 of the
approved specification. `additionalCommands` contains all exact additional
commands named above, both canonical version commands, the runtime and
metadata/inventory/hygiene checks, setup receipts, and any retained
security-fault receipt. Every command receipt has this shape:

```json
{
  "id": "unique-receipt-id",
  "command": "exact command",
  "status": "PASS",
  "exitStatus": 0,
  "trustedToolchainFingerprintSha256": "64 lowercase hexadecimal characters",
  "evidence": {
    "path": "relative/path/to/retained-command-output",
    "sha256": "64 lowercase hexadecimal characters"
  }
}
```

All 26 required `adversarial` cases and both `platforms` map to those receipt
IDs. A
`PASS` must name at least one receipt. A `HOLD` must name a `knownHolds` ID;
skips and unnamed incomplete cases are rejected. Passed Linux and macOS
platform entries must say `freshClone: true`. The generator requires every
Section 9 command and every required additional command separately on every
passed platform; a union of partial platform runs does not pass.

`toolchains` binds one retained, parsed toolchain receipt per passed platform:

```json
{
  "platform": "macos",
  "receiptId": "macos-toolchain",
  "trustedToolchainFormat": "absolute-executables-v1",
  "trustedToolchainFingerprintSha256": "64 lowercase hexadecimal characters",
  "trustedSupplementalToolPath": "/exact/scanner/bin:/exact/go/bin",
  "rustcVersion": "parsed release",
  "rustcHost": "parsed host",
  "executables": {
    "git": {
      "path": "/usr/bin/git",
      "sha256": "64 lowercase hexadecimal characters",
      "identity": "git version ..."
    }
  },
  "supplementalExecutables": {
    "go": {
      "path": "/exact/go/bin/go",
      "sha256": "64 lowercase hexadecimal characters",
      "identity": "go version ..."
    }
  },
  "evidence": {
    "path": "receipts/macos-toolchain.txt",
    "sha256": "64 lowercase hexadecimal characters"
  }
}
```

The executable maps above are abbreviated for readability. The derived core
map is exhaustive, and a nonempty supplemental path requires exactly
`gitleaks`, `cargo-audit`, `cargo-deny`, and `go`.

`assembly.securityReports` binds one full preflight report and exact sidecar
per passed platform. `cloneProvenance` binds the creation receipt, in-clone
verification receipt, canonical marker, and marker digest for every passed
platform. The corresponding `linux_fresh_clone` or `macos_fresh_clone` case
must map to both receipts. `supplementalEvidence` binds exactly one assembly
plan and one rich runtime JSON per passed platform. The manifest generator
re-hashes those files as well as every raw command receipt.

`versionIdentity` binds `canonical`, `binaryJson`, `changelog`,
`releaseProposition`, `packageMetadata`, and `archiveMetadata` to `0.1.0`;
`binaryText` is exactly `omnis-key 0.1.0`; and `receiptIds` names the retained
version-command receipts. `compatibilityBase` is derived as `0.61.2`. The
assembler parses both complete binary outputs rather than trusting these
summary fields. The generator independently rechecks the package,
archive prefix, changelog, proposition, specification, license, all platform
security reports, and every referenced evidence digest before writing the
manifest. It then loads the candidate-tracked assembler, verifies those bytes
against the candidate commit, deterministically reassembles the index from
the bound raw plan/receipts/archive/security reports, and requires exact
object equality with the supplied index. A hand-authored assembler-shaped
index or command-name-only payload is refused.

The exact required command strings and adversarial case IDs are constants in
`scripts/generate_builder_manifest.py`. Evidence files are resolved relative
to the verification index and may not be symlinks or escape its directory.
