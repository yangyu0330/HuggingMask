# PR #17 review response evidence - restricted runtime follow-up

## Scope

PR #17 restricted runtime review follow-up after the latest Issue #25 fix.

Reviewed target:

- PR: #17
- Head commit checked: `defabc3`
- Security fix commit included: `392faf4` (`[fix] runtime: sanitize preserve stdlib sys/builtins refs (Issue #25)`)

## Review Items Rechecked

The latest PR head includes regression coverage for the previously blocking restricted-runtime bypasses:

- import allowlist is enforced, and non-allowlisted `json` import is blocked by default.
- `extra_import_allowlist` is forwarded and permits only explicitly added modules.
- direct `builtins`, `io`, and `pathlib` import bypass attempts do not pass.
- `object.__subclasses__()` based recovery of real builtins does not pass.
- `typing.sys._getframe()` frame-introspection access does not pass.
- preserve-stdlib bypasses through `dataclasses.sys`, `enum.bltns`, `enum.sys`, and `collections._sys` do not pass and do not create file side effects.
- normal `@dataclass` usage still passes after the preserve-stdlib sanitization change.
- `torch` and `numpy` allowlist entries are documented/tested as fail-closed when their internal imports hit denylisted modules.

## Verification

Restricted runtime test suite:

```text
python -m pytest tests/test_restricted_runtime.py -q
85 passed, 1 skipped in 7.40s
```

Raw log:

- `evidence/tests/20260520_pr17_restricted_runtime_pytest_raw_KMW_v1.txt`

Full repository test suite:

```text
python -m pytest -q
417 passed, 1 skipped in 15.89s
```

Raw log:

- `evidence/tests/20260520_pr17_full_pytest_raw_KMW_v1.txt`

## Merge Readiness Notes

The previously blocking security review items are covered by code and regression tests in the PR head. This evidence update records the latest verification after the Issue #25 fix.
