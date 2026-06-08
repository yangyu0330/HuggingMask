#!/usr/bin/env bash
# HuggingMask — 샌드박스 이미지 빌드 (WSL2/Linux Docker에서 실행)
#
#   bash scripts/build_sandbox_images.sh
#
# 두 이미지를 빌드한다:
#   1) huggingmask-b2-sandbox:local — B-2 gVisor 커스텀 코드 샌드박스 (양유상)
#   2) weight-sandbox               — 피클 Path B 가중치 샌드박스 (정은미)
#
# 빌드 컨텍스트는 레포 루트여야 한다(Dockerfile 의 COPY 경로가 루트 기준).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

B2_IMAGE="${B2_IMAGE:-huggingmask-b2-sandbox:local}"
WEIGHT_IMAGE="${WEIGHT_IMAGE:-weight-sandbox}"

echo "==> 레포 루트: $REPO_ROOT"

echo "==> [1/2] B-2 gVisor 샌드박스 이미지 빌드: $B2_IMAGE"
docker build -f sandbox/image/b2/Dockerfile -t "$B2_IMAGE" .

echo "==> [2/2] 피클 Path B 가중치 샌드박스 이미지 빌드: $WEIGHT_IMAGE"
echo "    (torch/safetensors/numpy 설치 — 수 분 소요)"
docker build -f analyzer/assets/Dockerfile.sandbox -t "$WEIGHT_IMAGE" .

echo "==> 완료. 빌드된 이미지:"
docker image ls | grep -E "huggingmask-b2-sandbox|weight-sandbox" || true
echo "==> 검증:  bash scripts/check_gvisor_setup.sh"
