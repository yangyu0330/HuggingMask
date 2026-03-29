# hm-05-bad-config-automap

악성 config 차단 시나리오입니다.

## 목적
- `.py` 파일은 정상이어도 `config.json`의 트리거 필드 때문에 차단될 수 있음을 보여준다.
- 설정 파일도 단순 데이터가 아니라 실행 경로를 여는 입력이라는 점을 강조한다.

## 핵심 파일
- `config.json`
- `modeling_safe.py`
- `model.safetensors` (추후 생성)

## 중요 조건
- `modeling_safe.py`는 반드시 정상 상태를 유지한다.
- 차단 원인은 config trigger여야 하며, `.py` 자체가 원인이 되면 안 된다.

## 발표 포인트
- 설정 파일도 실행 경로를 열 수 있다.
- 정상 코드가 있어도 비승인 trigger는 기본 차단한다.
