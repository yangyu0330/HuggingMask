# hm-03-bad-pkl-reduce

악성 pickle 차단 시나리오입니다.

## 목적
- 정상 pickle과 거의 같은 구조에서 `REDUCE` 계열 opcode 하나만으로 차단되는 점을 보여준다.
- 실제 악성 행위 없이 harmless marker-only payload로 안전하게 시연한다.

## 핵심 파일
- `config.json`
- `pytorch_model.bin` (추후 생성)
- `malicious_marker.py`

## 발표 포인트
- 비슷해 보이는 모델도 실행 opcode 하나 때문에 즉시 차단된다.
- Path B에서 우회 실행 가능성이 있더라도 최종 배포는 Path A 기준으로 막는다.
