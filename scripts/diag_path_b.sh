#!/usr/bin/env bash
# HuggingMask — 피클 Path B 진단 (WSL2에서 실행)
#
#   bash scripts/diag_path_b.sh
#
# 목표: DOCKER_TIMEOUT 원인을 숫자로 확정한다.
#   1) weight-sandbox 를 CPU-torch Dockerfile 로 재빌드 (28b4af7 반영)
#   2) runsc vs runc 의 `import torch` 시간 측정
#   3) 실제 entrypoint(load_and_extract.py) e2e 시간 측정 (runsc)
# 측정값을 보고 분기: timeout 상향 / runc fallback / torch-free / 정직결론.

set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMAGE="${WEIGHT_IMAGE:-weight-sandbox}"

echo "════════════════════════════════════════════════════════════"
echo " Path B 진단  (image=$IMAGE)"
echo "════════════════════════════════════════════════════════════"

echo
echo "==> [1/4] weight-sandbox 재빌드 (CPU torch Dockerfile)"
echo "    CUDA torch가 남아 있으면 이 단계가 진짜 수정입니다."
docker build -f analyzer/assets/Dockerfile.sandbox -t "$IMAGE" . || {
  echo "    ✗ 빌드 실패 — 위 로그 확인"; exit 1; }

echo
echo "==> [2/4] torch import 시간:  runsc"
docker run --runtime=runsc --rm "$IMAGE" \
  python -c "import time;t=time.time();import torch;print('RUNSC torch import: %.2fs'%(time.time()-t))" \
  || echo "    ✗ runsc 실행 실패"

echo
echo "==> [2.5/4] torch import 시간:  runc (대조군)"
docker run --runtime=runc --rm "$IMAGE" \
  python -c "import time;t=time.time();import torch;print('RUNC  torch import: %.2fs'%(time.time()-t))" \
  || echo "    ✗ runc 실행 실패"

echo
echo "==> [3/4] 실제 entrypoint e2e (runsc, 데모와 동일한 zip-pkl)"
TMP="$(mktemp -d /tmp/hm-pb-diag.XXXXXX)"
PKL="$TMP/model.pkl"
# 데모와 동일: torch.save zip 포맷 (호스트 venv 의 torch 사용; 없으면 컨테이너로 생성)
if python3 -c "import torch" 2>/dev/null; then
  python3 -c "import torch; torch.save({'weight': torch.zeros(4)}, '$PKL')"
else
  docker run --rm -v "$TMP:/out" "$IMAGE" \
    python -c "import torch; torch.save({'weight': torch.zeros(4)}, '/out/model.pkl')"
fi
echo "    pkl 생성: $(ls -l "$PKL" | awk '{print $5" bytes"}')"

NONCE="diagnonce$$"
echo "    --- entrypoint 실행 (runsc, --read-only --network=none, 동일 조건) ---"
START=$(date +%s.%N)
docker run --rm --network=none --read-only --memory=1g --cpus=1 --runtime=runsc \
  -e "HM_SANDBOX_NONCE=$NONCE" \
  -v "$PKL:/input/model.pkl:ro" \
  "$IMAGE" python /app/load_and_extract.py /input/model.pkl
RC=$?
END=$(date +%s.%N)
echo "    --- e2e 시간: $(echo "$END - $START" | bc)s  (rc=$RC) ---"
rm -rf "$TMP"

echo
echo "==> [4/4] 판단 가이드"
cat <<'EOF'
    RUNSC torch import / e2e 시간을 현재 타임아웃(120s)과 비교:
      • e2e < 60s   → 재빌드만으로 해결. run_dashboard_wsl2.sh 재기동 후 데모 PASS 예상.
      • 60~110s     → 동작하지만 빠듯 → HUGGINGMASK_PATH_B_TIMEOUT=300 권장.
      • > 120s 반복 → runc-import 가 빠르면 'Path B 가중치 샌드박스만 runc' 또는
                      torch-free unpickler 검토. 느린 원인을 결과로 붙여주세요.
EOF
echo "════════════════════════════════════════════════════════════"
echo "이 출력 전체를 복사해서 붙여주세요. 분기 판단하겠습니다."
