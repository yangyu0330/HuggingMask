#!/usr/bin/env bash
# HuggingMask — runsc-strace 런타임 등록 (B-2 strace 게이트 통과용)
#
#   bash scripts/setup_runsc_strace.sh
#
# 제 #55 하드닝(require_runsc_strace=True)은 실제 runsc syscall 트레이스를
# 관측해야 B-2를 clean 인증한다. 그러려면 runsc 런타임이 ``--strace --debug
# --debug-log=<dir>`` 로 구성돼 strace 로그를 남겨야 한다(gVisor 공통 운영 원칙).
#
# 기존 ``runsc`` 런타임은 그대로 두고, strace 켜진 ``runsc-strace`` 런타임을
# 추가 등록한다. 데모는 ``--docker-runtime runsc-strace --runsc-strace-log-dir <dir>``
# 로 그 로그를 읽어 strace_observed=True → clean review 판정.

set -uo pipefail

LOG_DIR="${RUNSC_STRACE_LOG_DIR:-/tmp/runsc-strace}"
RUNTIME_NAME="${RUNSC_STRACE_RUNTIME:-runsc-strace}"

echo "==> strace 로그 디렉토리: $LOG_DIR"
sudo mkdir -p "$LOG_DIR"
sudo chmod 0777 "$LOG_DIR"

echo "==> [$RUNTIME_NAME] 런타임 등록 (--strace --debug --debug-log=$LOG_DIR/)"
# gVisor 표준: runsc install --runtime <name> -- <runtimeArgs>
sudo runsc install --runtime "$RUNTIME_NAME" -- --strace --debug --debug-log="$LOG_DIR/"

echo "==> docker 재시작"
sudo service docker restart 2>/dev/null || sudo systemctl restart docker 2>/dev/null || true
sleep 2

echo "==> 확인"
if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q "$RUNTIME_NAME"; then
  echo "  ✓ $RUNTIME_NAME 런타임 등록됨"
else
  echo "  ✗ 미등록 — 'sudo runsc install --runtime $RUNTIME_NAME -- --strace --debug --debug-log=$LOG_DIR/' 출력 확인"
fi

echo
echo "────────────────────────────────────────────"
echo "이제 strace 캡처 데모:"
echo "  python3 scripts/demo_b2_run.py \\"
echo "    --image-ref huggingmask-b2-sandbox:local \\"
echo "    --docker-runtime $RUNTIME_NAME \\"
echo "    --runsc-strace-log-dir $LOG_DIR \\"
echo "    --evidence-dir ~/hm-evidence"
echo
echo "기대: decision = B2_POLICY_REVIEW_REQUIRED (strace 관측 → clean)"
echo
echo "대시보드 서버에도 적용하려면:"
echo "  export HUGGINGMASK_B2_RUNTIME=$RUNTIME_NAME"
echo "  export HUGGINGMASK_B2_STRACE_LOG_DIR=$LOG_DIR"
