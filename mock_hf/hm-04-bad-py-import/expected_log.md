# Expected Log - hm-04-bad-py-import

```text
[Proxy] request_id=<uuid> repo=hm-04-bad-py-import
[Proxy] file classified: modeling_evil.py -> PYTHON
[Validation] route=CODE_AST_SCAN
[Validation] ast parse success
[Validation] dangerous call detected: __import__
[Validation] grade=C
[Validation] status=BLOCK decision=DENY
[Proxy] release_action=DENY
```
