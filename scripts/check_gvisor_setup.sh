#!/usr/bin/env bash
# HuggingMask — WSL2 + Docker + gVisor(runsc) 셋업 검증
#
# WSL2 Ubuntu 안에서 실행하세요:
#   bash scripts/check_gvisor_setup.sh
#
# 각 전제조건을 ✓/✗ 로 점검하고, 미충족 항목마다 다음 할 일을 안내합니다.
# 모두 ✓ 면 대시보드 '모델 검사'에서 B-2(gVisor)와 피클 Path B 단계가
# 실제로 실행됩니다. exit code = 미충족 개수.

set -u

B2_IMAGE="${B2_IMAGE:-huggingmask-b2-sandbox:local}"
WEIGHT_IMAGE="${WEIGHT_IMAGE:-weight-sandbox}"

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else G=; R=; Y=; B=; N=; fi
fail=0
ok()   { echo "  ${G}✓${N} $1"; }
bad()  { echo "  ${R}✗${N} $1"; fail=$((fail+1)); }
hint() { echo "      ${Y}→ $1${N}"; }

echo "${B}HuggingMask gVisor/Docker 셋업 검증${N}"
echo "────────────────────────────────────────────"

# 1. Linux 커널 (gVisor는 Linux 전용)
echo "${B}[1] Linux 환경${N}"
if [ "$(uname -s)" = "Linux" ]; then
  ok "Linux 커널 ($(uname -r))"
else
  bad "Linux 아님 ($(uname -s)) — gVisor는 Linux에서만 동작"
  hint "Windows PowerShell(관리자)에서: wsl --install -d Ubuntu  후 Ubuntu 안에서 다시 실행"
fi

# 2. Docker CLI
echo "${B}[2] Docker CLI${N}"
if command -v docker >/dev/null 2>&1; then
  ok "docker 있음 ($(docker --version 2>/dev/null | head -1))"
else
  bad "docker 명령 없음"
  hint "Docker Desktop의 WSL2 integration을 켜거나, WSL2 안에 Docker Engine 설치"
fi

# 3. Docker 데몬 접근
echo "${B}[3] Docker 데몬${N}"
if docker info >/dev/null 2>&1; then
  ok "데몬 접근 가능"
else
  bad "데몬에 연결 불가"
  hint "Docker Desktop 실행 + Settings > Resources > WSL Integration 에서 이 배포판 체크"
  hint "또는 WSL2 네이티브: sudo service docker start"
fi

# 4. runsc 런타임 등록
echo "${B}[4] gVisor runsc 런타임 등록${N}"
runtimes="$(docker info --format '{{json .Runtimes}}' 2>/dev/null)"
if echo "$runtimes" | grep -q "runsc"; then
  ok "docker info 에 runsc 등록됨"
else
  bad "runsc 런타임 미등록"
  hint "설치:  sudo apt-get update && sudo apt-get install -y runsc   (gVisor apt repo 필요, 가이드 참고)"
  hint "등록:  sudo runsc install && sudo systemctl restart docker   (또는 sudo service docker restart)"
fi

# 5. runsc smoke test (실제 실행)
echo "${B}[5] runsc 실행 스모크 테스트${N}"
if docker info >/dev/null 2>&1 && echo "$runtimes" | grep -q "runsc"; then
  if docker run --runtime=runsc --rm hello-world >/dev/null 2>&1; then
    ok "docker run --runtime=runsc hello-world 성공"
  else
    bad "runsc 로 컨테이너 실행 실패"
    hint "수동 확인:  docker run --runtime=runsc --rm hello-world"
    hint "WSL2 커널이 gVisor 요구사항을 못 맞추면 .wslconfig 에 kernel 옵션 필요할 수 있음(가이드 참고)"
  fi
else
  bad "선행 조건(데몬/runsc 등록) 미충족 — 스모크 테스트 건너뜀"
fi

# 6. B-2 gVisor 이미지
echo "${B}[6] B-2 샌드박스 이미지 ($B2_IMAGE)${N}"
if docker image inspect "$B2_IMAGE" >/dev/null 2>&1; then
  ok "이미지 빌드됨"
else
  bad "이미지 없음"
  hint "빌드:  bash scripts/build_sandbox_images.sh   (또는 docker build -f sandbox/image/b2/Dockerfile -t $B2_IMAGE .)"
fi

# 7. 피클 Path B (weight-sandbox) 이미지
echo "${B}[7] 피클 Path B 이미지 ($WEIGHT_IMAGE)${N}"
if docker image inspect "$WEIGHT_IMAGE" >/dev/null 2>&1; then
  ok "이미지 빌드됨"
else
  bad "이미지 없음"
  hint "빌드:  bash scripts/build_sandbox_images.sh   (또는 docker build -f analyzer/assets/Dockerfile.sandbox -t $WEIGHT_IMAGE .)"
fi

# 8. Python venv (선택 — 서버 구동용)
echo "${B}[8] Python (서버 구동용, 선택)${N}"
if command -v python3 >/dev/null 2>&1; then
  ok "python3 있음 ($(python3 --version 2>&1))"
else
  bad "python3 없음 (서버를 WSL2 안에서 띄우려면 필요)"
  hint "sudo apt-get install -y python3 python3-venv python3-pip"
fi

echo "────────────────────────────────────────────"
if [ "$fail" -eq 0 ]; then
  echo "${G}${B}모든 전제조건 충족 ✓${N}"
  echo "이제 WSL2 안에서 서버를 띄우고 환경변수를 켜면 대시보드에서 실제 실행됩니다:"
  echo "  export HUGGINGMASK_ENABLE_REAL_SANDBOX=1"
  echo "  export HUGGINGMASK_ENABLE_PATH_B=1"
  echo "  uvicorn proxy.app.main:app --port 8000"
else
  echo "${R}${B}미충족 $fail 개${N} — 위 → 안내를 순서대로 처리한 뒤 다시 실행하세요."
  echo "상세 가이드: docs/WSL2_GVISOR_SETUP_KMW.md"
fi
exit "$fail"
