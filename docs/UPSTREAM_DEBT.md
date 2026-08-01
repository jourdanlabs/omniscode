# Inherited guardrail debt

The full inherited guardrail suite is **not green**. V1 uses the specification's
truthful baseline-and-no-regression path; the baseline is not a waiver.

## Frozen observation

At implementation starting commit
`670955adf1eebb207bc4a4411e5f6083562d167c`, the checked-in ratchets record:

- 107 production Rust files already above the 1,200-line threshold;
- 38 test Rust files already above the 1,200-line threshold;
- 3,231 swallowed-error-like occurrences across 490 tracked files
  (`let _ =`, `.ok()`, and `.unwrap_or_default()`);
- 60 panic-prone production occurrences across 19 tracked files.

The same starting commit already exceeds stale checked-in baselines:

- code-size: 15 inherited oversized production files had grown beyond their
  recorded line counts;
- test-size: 4 inherited oversized test files had grown beyond their recorded
  line counts;
- swallowed errors: 3 occurrences were present in two new production files
  not represented by the baseline.

These are inherited findings, not claims that the code is acceptable. Exact
paths and counts are reproduced by:

```bash
git switch --detach 670955adf1eebb207bc4a4411e5f6083562d167c
python3 scripts/check_code_size_budget.py
python3 scripts/check_test_size_budget.py
python3 scripts/check_panic_budget.py
python3 scripts/check_swallowed_error_budget.py
```

Expected status at that identity is nonzero for code size, test size, and
swallowed errors. Panic count reports an improvement where the live count is
below the stale baseline.

## Release rule

Release changes may not add an unrecorded warning, oversized file/test,
panic-prone use, swallowed-error-like use, dependency-boundary violation, or
wildcard re-export. Strict clippy must pass for release-owned crates and code.

Do not run a baseline `--update` merely to make the candidate green. A baseline
change must enumerate each delta, distinguish inherited cleanup from release
growth, and receive independent review. The final evidence packet records both
the inherited debt and the release-diff result.
