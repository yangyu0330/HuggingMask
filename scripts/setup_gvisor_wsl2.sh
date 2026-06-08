#!/usr/bin/env bash
# HuggingMask — WSL2 Ubuntu 네이티브 Docker Engine + gVisor(runsc) 자동 설치
#
#   bash scripts/setup_gvisor_wsl2.sh
#
# gVisor 는 Docker Desktop 데몬에 등록하기 어렵다(자체 VM). 그래서 WSL2 Ubuntu
# 안에 네이티브 Docker Engine 을 깔고 runsc 를 등록한다. 내부에서 sudo 를 쓰므로
# 루트가 아닌 일반 사용자로 실행한다. 멱등(이미 된 단계는 건너뜀).
#
# 주의: Docker Desktop 의 WSL Integration 이 이 배포판에 켜져 있으면 소켓이
# 충돌할 수 있다. 그 경우 Docker Desktop > Settings > Resources > WSL Integration
# 에서 이 배포판 체크를 해제하고 다시 실행한다.

set -uo pipefail

step() { echo; echo "==> $1"; }
ok()   { echo "  ✓ $1"; }
warn() { echo "  ! $1"; }

ARCH="$(dpkg --print-architecture)"

# ── 1. 네이티브 Docker Engine ────────────────────────────────────────
step "[1/4] 네이티브 Docker Engine"
if command -v dockerd >/dev/null 2>&1; then
  ok "dockerd 이미 설치됨"
else
  echo "  get.docker.com 설치 스크립트 실행..."
  curl -fsSL https://get.docker.com | sudo sh
fi
sudo usermod -aG docker "$USER" 2>/dev/null || true
# WSL2 는 systemd 가 꺼져 있을 수 있으므로 service 로 기동
sudo service docker start 2>/dev/null || sudo systemctl start docker 2>/dev/null || true
sleep 2
if sudo docker info >/dev/null 2>&1; then
  ok "docker 데몬 기동됨"
else
  warn "데몬 기동 실패 — 'sudo dockerd' 로 직접 띄워 에러를 확인하거나 WSL 재시작 후 재시도"
fi

# ── 2. gVisor runsc 설치 ─────────────────────────────────────────────
step "[2/4] gVisor runsc 설치"
if command -v runsc >/dev/null 2>&1; then
  ok "runsc 이미 설치됨 ($(runsc --version 2>/dev/null | head -1))"
else
  sudo apt-get update
  sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
  curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
  sudo apt-get update
  sudo apt-get install -y runsc
  ok "runsc 설치 완료"
fi

# ── 3. Docker 에 runsc 런타임 등록 ───────────────────────────────────
step "[3/4] Docker 에 runsc 런타임 등록"
sudo runsc install
sudo service docker restart 2>/dev/null || sudo systemctl restart docker 2>/dev/null || true
sleep 2
if sudo docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc; then
  ok "runsc 런타임 등록됨"
else
  warn "runsc 가 docker info 에 안 보임 — 데몬 재시작 확인 필요"
fi

# ── 4. runsc 스모크 테스트 ───────────────────────────────────────────
step "[4/4] runsc 스모크 테스트 (hello-world)"
if sudo docker run --runtime=runsc --rm hello-world >/dev/null 2>&1; then
  ok "docker run --runtime=runsc hello-world 성공"
else
  warn "runsc 실행 실패 — 'sudo docker run --runtime=runsc --rm hello-world' 로 직접 에러 확인"
fi

echo
echo "────────────────────────────────────────────"
echo "완료. 다음:"
echo "  1) 새 셸을 열거나  newgrp docker  (docker 그룹 적용 → sudo 없이 docker)"
echo "  2) bash scripts/check_gvisor_setup.sh   (전체 ✓ 확인)"
echo "  3) bash scripts/build_sandbox_images.sh (이미지 빌드)"
