# OMNIS Key Checkpoint Authority (Source Contract)

The checkpoint authority is the first OMNIS Key component intentionally
designed to run outside the jcode user's security identity. Its positive claim
is narrow:

> A successful fixed-authority anchor operation proves that a separately
> identified local authority key signed one exact, monotonically extending
> receipt-head assertion and published it into the authority's then-current,
> fsynced record chain.

This is separate retention, not independent evidence validation. The authority
does not approve an action, execute a tool, validate the truth of cited
evidence, call a provider, or create production authority.

## Source-only boundary

This checkpoint-authority increment contains a daemon, protocol, client, and
verification kernel. It contains no checkpoint-authority installer,
service-account creator, key provisioner, launchd activation, credential
migration, or automatic fallback. Inherited installation scripts are
quarantined from the V1 tree; no retained command provisions or activates this
authority.

The daemon's production entrypoint takes zero arguments and requires all
authority material to exist already. Missing or drifting activation state
refuses. No installation, service launch, key creation, host activation, or
running authority is authorized by these source bytes. Production client and
daemon entrypoints refuse on non-macOS platforms.

The fixed macOS paths are:

```text
/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/activation.v1.json
/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/authority.ed25519.pub
/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/v1/authority.ed25519.pk8
/Library/Application Support/JourdanLabs/OMNIS Key/Checkpoint Authority/v1/records
/var/run/jourdanlabs/omnis-checkpointd.sock
```

The root-owned activation manifest, together with the fixed production
configuration, pins the service UID, primary GID, complete canonical group
vector including that primary GID, allowed client UID, logical ledger identity, exact
absolute normalized receipt-ledger path, and every authority path. The
manifest repeats the socket, records, private-key, and trust-key paths; the
production configuration fixes the activation path and authority root.

The receipt path is repeated in every anchor request and signed record.
Ambient `HOME`, `JCODE_HOME`, and `JCODE_RUNTIME_DIR` cannot substitute
another ledger under the pinned identity. The fixed checkpoint CLI commands
are intercepted before jcode logging, cleanup, configuration migration,
telemetry, provider setup, or background update/re-exec. Every OMNIS command
is also excluded from the normal background updater.

The daemon refuses group 0, identity drift, client/service UID reuse,
unexpected paths, symlinks on controlled activation/authority paths,
socket-parent or socket-leaf type drift, unsafe controlled-object modes,
extended ACLs on controlled objects, and a signing key that does not match the
separately supplied root-owned trust key. It reopens
the activation file, validates it, and exact-compares its bytes with startup
authority before every connection operation, then rechecks the process UID,
primary GID, and full group vector. The production client separately checks
the root-owned activation and trust files, the server socket owner/GID/mode,
the connected server's kernel-reported UID/GID, and every returned signed
checkpoint.

Test-only explicit configuration is compiled only for crate tests. The
authority store and signing identity are not normal public crate APIs.

This increment does not implement a reviewed pre-exec environment scrub,
inherited-file-descriptor closure, executable ownership/code-signing check, or
launcher. Dynamic-loader and executable provenance are therefore installer
and activation-gate requirements, not claims of this source gate.

## Monotonic protocol

An anchor request contains:

1. a stable request ID;
2. the activation-pinned ledger identity and exact receipt-ledger path;
3. the previous checkpoint hash, if one exists;
4. the asserted receipt sequence and head;
5. each receipt-link witness after the prior checkpoint.

The `omnis-key checkpoint anchor` source CLI first verifies the pinned local
receipt file as a valid OMNIS receipt chain and checks that the ledger is a
private client-owned `0600` file under a client-owned `0700` directory,
without symlinks or extended ACLs. `CheckpointClient::anchor` by itself does
not open or validate receipt payloads.

The authority obtains the caller UID from the Unix socket; it does not accept
a claimed UID in JSON. The first checkpoint must present links from sequence
1. Later checkpoints must begin exactly after the last observed receipt, name
the last signed checkpoint, and form one gapless parent-hash chain to the
requested head. Rollback, fork, gap, reorder, no-advance, wrong-path,
wrong-ledger, wrong-peer, and request-ID drift refuse.

The daemon does not independently open the user's receipt file or recompute
receipt payload hashes. It signs exact link witnesses submitted by the
allowed UID after enforcing continuity against its prior checkpoint. Code
running as that UID can submit directly to the bounded client/protocol
interface. The authority is therefore a separately retained high-water
assertion, not an independent witness to evidence truth.

One request carries at most 4,900 link witnesses so even the worst
model-valid sequence and maximum identifiers remain below the one-mebibyte
wire frame. For a longer unanchored suffix, the CLI emits deterministic
derived-ID intermediate checkpoints and uses the caller's stable ID only for
the final head. The internal `anchor-segment:` namespace is refused for caller
final IDs, and the caller ID is validated before any authority access.
Authority status lets a retry resume after a lost intermediate response.
Lookup recovers a lost final response only while the freshly re-read local
head still equals that final checkpoint.

An exact semantic replay of the same parsed request ID, request fields, and
peer UID returns the existing signed checkpoint without appending a duplicate.
Raw JSON whitespace and omitted-versus-null optional fields are not distinct
replay identities. Reusing a final request ID after the local head advances
refuses instead of returning a stale prefix as current.

After the authority responds, the CLI rechecks the ledger boundary and
re-verifies the local chain. Anchor success requires the returned checkpoint
to equal that final local head. A concurrent suffix or rewrite therefore
refuses. This is fail-closed but not transactional across the two identities:
the authority may already have durably appended the submitted snapshot before
the CLI detects a raced local advance and returns an error. Inspect authority
status and use a new stable ID for a later, advanced head.

The source CLI exposes these fixed-authority operations:

```text
omnis-key checkpoint anchor --request-id <stable-id>
omnis-key checkpoint verify-anchored
```

They expose no authority socket, key, ledger identity, or receipt-path
override. `verify-anchored` verifies that the authority's latest signed
checkpoint still exists as an exact prefix in the current valid local chain;
it does not claim that a subsequently appended local suffix is already
anchored. The exact CLI response names the observed checkpoint and receipt
sequence and hashes; this document supplies the narrower claim ceiling:
separately retained local-head assertion, not evidence validation.

## Persistence and restart

Each checkpoint is an Ed25519-signed, domain-separated record chained to the
previous checkpoint hash. Records use monotonically numbered immutable
filenames. The normal writer writes and fsyncs a same-directory temporary
file, publishes the final sequence name through an exclusive hard link, and
fsyncs the records directory. Before reporting success it also requires
temporary-name removal and a second directory fsync. It never overwrites an
existing numbered record.

At startup and before every status, lookup, or mutation, the authority verifies
the complete available record chain, every signature, every record hash,
sequence continuity, request/record pairing, and filename binding. Internal
gaps, alterations, partial numbered records, and forks refuse. An empty
records directory is a valid genesis state; this fact is part of the
authority-compromise ceiling below.

The daemon holds a nonblocking advisory exclusive lock on the validated
records-directory file descriptor for the listener lifetime. On macOS, restart
recovers only a correctly owned/mode-set stale socket or one single
identity-bound quarantine residue after liveness, device/inode, exclusive
rename, and directory-fsync checks. An active listener, wrong identity or
mode, symlink, multiple residues, or raced replacement refuses. Production
sets a fixed `0117` umask once in the dedicated zero-argument process and does
not pathname-`chmod` the production socket after binding.

## Exact claim ceiling

With a correctly gated, uncompromised host activation, separating the ordinary
jcode UID from the checkpoint service UID prevents the ordinary client from
rewriting the authority's private key and records. This source candidate does
not prove that the account, group topology, filesystem ownership, trust key,
executable, launcher, or launchd service exists on any host.

The service UID holds the signing key and records. Compromise of that identity
can sign fabricated future extensions, ignore the advisory lock, and
coherently delete, rewrite, or regrow history. Root can additionally replace
activation, trust, executable, and filesystem authority. A separately retained
external high-water witness can expose rollback only up to the state it
witnessed; it does not prevent or detect all online forgery after signing-key
compromise.

The fixed socket parent is root-owned, service-group `0770`, while the socket
is service-owned `0660`. A nonroot client granted that group for connectivity
can unlink, rename, or preplant directory entries and deny availability. Peer
credentials, socket identity checks, signed checkpoints over the
peer-authenticated socket, restart refusal, and the private authority key
preserve the stated authenticity boundary; they do not make an availability
claim. A reviewed installer/topology must use a dedicated service group and
explicitly accept or eliminate this denial path.

No broader rollback, hardware-root, remote-transparency, execution, action
approval, installer, activation, provider, Door, publication, or LIVE claim
is made.
