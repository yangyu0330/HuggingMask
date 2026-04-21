# Code Validation Regression Fixtures

These fixtures are lightweight regression scenarios inspired by the old
`mock_hf` idea, but intentionally rebuilt for direct validator integration
tests.

- No Hub download/fetch
- No proxy endpoint
- No orchestrator final responsibility
- No whitelist DB/pending store/review queue/runtime execution
- Runtime is represented only by `runtime_check` stubs

Each scenario folder contains:

- `fixture_manifest.json`: how to run and what to assert
- source files (`.py` / `.json`)
- optional runtime/context metadata stubs
