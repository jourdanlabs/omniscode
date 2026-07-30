## Exact change

Describe the behavior and claim ceiling changed.

## Verification

List exact commands and exit statuses. Include zero-attempt network and
allowed-write evidence when relevant.

## Rights and fixtures

List every added asset/fixture, its source, license, and required notice.
Confirm all fixtures are synthetic and contain no private or credential
material.

## Limits / HOLD

Name any unresolved limit or reproducible HOLD. Do not issue `CLEAR`; an
independent reviewer binds verdicts to an immutable candidate.

## Checklist

- [ ] I read `docs/OPEN_SOURCE_V1_RELEASE_SPEC.md` and `docs/THREAT_MODEL.md`.
- [ ] I added adversarial refusal tests where the integrity boundary changed.
- [ ] I did not add provider spend, credentials, installation, activation, or publication behavior.
- [ ] I ran `git diff --check` and relevant format/clippy/tests.
