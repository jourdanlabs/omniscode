# Repository Guidelines

## Development Workflow

- **Commit as you go** - Make small, focused commits after completing each feature or fix
- If the git state is not clean, or there are other agents working in the codebase in parallel, do your best to still commit your work. 
- **Keep V1 work local until promotion** - Do not push, tag, publish, install,
  mutate hosted settings, or announce a V1 candidate. Those are
  Captain-controlled actions after independent review.
- **Run the guardrails before handoff** - `scripts/check_guardrails.sh` runs every gate in
  CI's Format + Quality Guardrails jobs (fmt, clippy `-D warnings`, and the warning,
  code-size, test-size, panic, swallowed-error, dependency-boundary, and wildcard-reexport
  ratchets). Use `--skip-slow` to skip cargo check/clippy, and `--fix` to rustfmt and
  rebaseline ratchets after intentional growth. The release specification pins
  the required verification matrix and candidate evidence.
- **Use fast iteration by default** - Prefer `cargo check`, targeted tests, and dev builds while iterating
- **Rebuild when done** - When you are done making changes, build the source.
- **Preserve the frozen V1 identity** - `omnis-key-cli` is the sole `0.1.0`
  product-version source. Do not improvise a release-version change.

## Logs
- Logs are written to `~/.jcode/logs/` (daily files like `jcode-YYYY-MM-DD.log`).

## Debug Socket
- Use the debug socket for runtime level debugging

## V1 Source-Only Boundary

- Build locally with Cargo; V1 ships no installer, updater, service unit, or
  privileged activation package.
- Do not exercise inherited stable/current/canary replacement channels during
  V1 development or verification.
- Provider commands are explicit user actions. Verification and demos remain
  fixture-only and credential-free.
