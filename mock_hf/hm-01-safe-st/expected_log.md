# Expected Log - hm-01-safe-st

```text
[Proxy] request_id=<uuid> repo=hm-01-safe-st
[Proxy] file classified: model.safetensors -> SAFETENSORS
[Validation] route=SAFETENSORS_FAST_PATH
[Validation] sha256 verified
[Validation] metadata schema valid
[Validation] status=PASS decision=APPROVE
[Proxy] release_action=APPROVE_AND_STORE
```

재요청 시 추가 기대 로그:

```text
[Proxy] cache_key=<sha256:file_kind:policy_fingerprint>
[Proxy] CACHE_HIT
```
