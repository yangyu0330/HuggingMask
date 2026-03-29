# hm-04-bad-py-import

악성 코드(.py) 차단 시나리오입니다.

## 목적
- config가 아니라 `.py` 본문이 문제라서 차단되는 흐름을 보여준다.
- AST 단계에서 위험 호출을 실행 없이 차단하는 점을 보여준다.

## 핵심 파일
- `config.json`
- `modeling_evil.py`
- `model.safetensors` (추후 생성)

## 중요 조건
- 이 시나리오는 데모 전용 정책 프로파일 `allow_custom_code_scan`을 사용한다.
- `strict_default`로 실행하면 config 단계에서 먼저 차단될 수 있으므로, 발표 메시지가 흐려진다.

## 발표 포인트
- 코드를 실제 실행하지 않고 AST 단계에서 위험 패턴을 차단한다.
- 악성 config와 악성 code는 차단 지점이 다르다.
