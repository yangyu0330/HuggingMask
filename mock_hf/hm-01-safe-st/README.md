# hm-01-safe-st

정상 safetensors 통과 시나리오입니다.

## 목적
- 안전한 포맷은 빠르게 통과하는 경로를 보여준다.
- 두 번째 요청에서 캐시 히트도 같이 시연한다.

## 핵심 파일
- `config.json`
- `model.safetensors` (추후 생성)

## 기대 결과
- `PASS`
- fast-path 통과
- cache hit 시 즉시 반환

## 발표 포인트
- 정상 모델은 느리게 만들지 않는다.
- 안전한 포맷은 경량 검증 후 바로 승인한다.
