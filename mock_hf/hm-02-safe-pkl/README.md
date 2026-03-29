# hm-02-safe-pkl

정상 data-only pickle 통과 시나리오입니다.

## 목적
- legacy pickle이라도 실행 가능한 opcode가 없으면 안전 서브셋으로 처리할 수 있음을 보여준다.
- 최종 배포는 원본 pickle이 아니라 Path A 변환 결과(safetensors)임을 보여준다.

## 핵심 파일
- `config.json`
- `pytorch_model.bin` (추후 생성)

## 제약
- 실제 대형 HuggingFace checkpoint를 쓰지 않는다.
- data-only dict 구조만 사용한다.

## 발표 포인트
- pickle 전체를 신뢰하지 않고 안전한 부분집합만 허용한다.
- 최종 배포는 safetensors로 정규화한다.
