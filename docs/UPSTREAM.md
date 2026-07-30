# Upstream relationship

OMNIS KEY Local Integrity V1 is a fork of
[`1jehuang/jcode`](https://github.com/1jehuang/jcode).

The provenance boundary is machine-readable in `provenance/upstream.json`.
The selected upstream base is:

```text
commit a3a24cdb3aee97ebb43fe84e79bfa63828f3a39a
tree   8e8aed923862573d6aa04e181e00acb7e86a20b1
```

The retained inherited chassis includes the TUI, provider integrations,
sessions, tools, memory, swarm, and internal `jcode` crate/config namespaces.
Desktop and iOS application source, executable targets, and build/test
harnesses are quarantined and absent from the V1 source tree. JourdanLabs does
not claim authorship of the retained inherited components or independent
reproduction of upstream performance claims.

JourdanLabs modifications broadly include local receipt integrity, atomic
safety receipt obligations, fail-closed reconciliation, the experimental
checkpoint source kernel, the `omnis-key` surface, fork-sovereignty controls,
tests, and public release/governance evidence.

The upstream MIT `LICENSE` is unchanged. Retained third-party assets have
separate inventory and notices. The jcode name and artwork identify inherited
compatibility material and do not imply endorsement.

## Release-tree quarantine

V1 removes the inherited telemetry deployment, binary installers, release-note
generator, quick-release/package-manager scripts, Discord/TestFlight/tag
workflows, deployment helpers, desktop and iOS application trees and harnesses,
historical release-note data, and nonessential demo/readme media from the
candidate tree. Git history is not rewritten.

The remaining active workflow is read-only OMNIS CI. A source release remains
blocked until independent review and Captain-controlled hosted promotion.

## Syncing upstream safely

Contributors may fetch upstream but should disable its push URL:

```bash
git remote add upstream https://github.com/1jehuang/jcode.git
git remote set-url --push upstream DISABLED
git fetch upstream
```

An upstream sync is a new candidate. Re-run sovereignty, integrity, rights,
archive, and independent gates; do not assume an earlier verdict carries over.
