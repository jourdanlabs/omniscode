# V1 threat model

## Protected properties

V1 aims to:

- bound each receipt frame before allocation;
- append one receipt per exact event and refuse replay collisions;
- detect malformed, partial, inconsistent, reordered, and hash-mismatched
  local receipt bytes;
- atomically preserve a terminal safety decision and its receipt obligation;
- refuse orphaned, drifted, or mismatched safety/receipt state;
- constrain default-created state to an owner-private, symlink-safe,
  ACL-reviewed local boundary;
- keep offline integrity commands free of ambient network and unrelated writes.

## Adversaries considered

- accidental interruption or receipt-write failure;
- malformed or truncated local files;
- local edits and record reordering;
- event-ID collision with nonidentical content;
- unsafe path components, modes, ownership, symlinks, or ACLs;
- inherited runtime behavior attempting telemetry, discovery, update, account,
  support, installation, or release access;
- release tooling that skips a secret, dependency, license, or artifact scan.

## Explicitly outside the claim

V1 does not establish:

- that cited evidence is true;
- that recording authorizes or executes an action;
- that every model turn, tool call, or completed task is receipted;
- protection from a malicious same-UID process that can delete the ledger,
  roll it back to an internally valid prefix, or coherently rewrite and rehash
  it;
- a total ledger/state-size bound (bounds are per record/frame);
- encryption at rest;
- a hardware root, remote transparency log, enterprise identity, regulatory
  compliance, or production availability;
- Windows crash durability or checkpoint support;
- an installed or operating checkpoint authority.

## Privacy

Receipt IDs, subjects, evidence digests, ledger data, checkpoint metadata, and
safety action/description/rationale/context may be plaintext. Do not put
secrets in event IDs or subjects. Treat local state as integrity data, not a
secret vault.

## Checkpoint ceiling

The experimental checkpoint kernel is intended to make some rollback visible
when an independently owned checkpoint is actually retained. V1 does not
install or activate that authority. Local tests must demonstrate—not hide—that
full-tail removal to a valid prefix is undetected without it.

## Release threats

The candidate is held if any required scan is absent, empty, incomplete, or
crashes; an inherited publication workflow remains active; an archive exceeds
the reviewed size; rights are unknown; identities disagree; or independent
review is missing. A builder may produce `BUILDER_CANDIDATE_READY` evidence but
may not issue `CLEAR`.
