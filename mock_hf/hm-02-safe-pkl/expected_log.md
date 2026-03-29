# Expected Log - hm-02-safe-pkl

```text
[Proxy] request_id=<uuid> repo=hm-02-safe-pkl
[Proxy] file classified: pytorch_model.bin -> PICKLE
[Validation] route=PICKLE_PATH_A
[Validation] opcode whitelist passed
[Validation] transform_to_safetensors success
[Validation] compare_with_path_b matched
[Validation] status=PASS decision=APPROVE_WITH_TRANSFORM
[Proxy] released_artifact=model.safetensors
```
