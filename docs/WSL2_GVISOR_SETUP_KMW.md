# WSL2 + Docker + gVisor 셋업 런북 (대시보드 8/8 실제 점등용)

> 목표: Windows 11 PC에서 **WSL2 Ubuntu + Docker + gVisor(runsc)** 를 갖춰,
> 대시보드 '모델 검사'의 **B-2 gVisor 샌드박스**와 **피클 Path B** 단계가
> 실제로 실행되게 한다. (나머지 6단계는 이미 Windows에서 실증됨)
>
> 기준 문서: [docs/B-2_WSL2_실행_시연_계획서.md](B-2_WSL2_실행_시연_계획서.md) §10
> 공식: https://gvisor.dev/docs/user_guide/install/

각 단계 끝에 **검증 명령**이 있다. `bash scripts/check_gvisor_setup.sh` 로
언제든 전체 상태를 ✓/✗ 로 확인할 수 있다.

---

## 0. 왜 WSL2인가
gVisor(`runsc`)는 **Linux 전용**이다. Windows 네이티브에선 안 돈다.
WSL2는 진짜 Linux 커널을 주므로 그 안에서 Docker + runsc 가 동작한다.
피클 Path B 샌드박스와 B-2 gVisor 샌드박스 둘 다 이 환경에서 실행된다.

---

## 1. WSL2 Ubuntu 설치 (Windows PowerShell 관리자)

```powershell
wsl --install -d Ubuntu
# 재부팅 요구하면 재부팅 후 Ubuntu 자동 실행 → 사용자/비밀번호 설정
wsl --set-default-version 2
wsl -l -v        # Ubuntu 가 VERSION 2 인지 확인
```

이후 명령은 **Ubuntu(WSL2) 터미널 안에서** 실행한다.
레포는 WSL2에서 다음 경로로 보인다:
```bash
cd /mnt/c/Users/minwo/Downloads/HuggingMask
```
> 성능을 원하면 레포를 WSL2 홈(`~/HuggingMask`)으로 복사해도 된다(선택).

**검증:** `uname -s` → `Linux`

---

## 2. Docker 준비 (둘 중 택1)

### 옵션 A — Docker Desktop WSL Integration (간단)
1. Docker Desktop 실행
2. Settings → Resources → **WSL Integration** → `Ubuntu` 체크 → Apply & Restart

### 옵션 B — WSL2 안에 Docker Engine 네이티브 설치
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"      # 로그아웃/재로그인 후 적용
sudo service docker start
```

**검증:** `docker info` 가 에러 없이 출력

---

## 3. gVisor(runsc) 설치 + Docker 런타임 등록 (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list > /dev/null
sudo apt-get update
sudo apt-get install -y runsc

# Docker 에 runsc 런타임 등록
sudo runsc install
sudo systemctl restart docker 2>/dev/null || sudo service docker restart
```

**검증:**
```bash
docker info | grep -iA2 runtimes      # runsc 가 보여야 함
docker run --runtime=runsc --rm hello-world   # 성공해야 함
```
> `hello-world` 가 runsc 로 성공하지 않으면 이후 단계로 가지 않는다.
> WSL2 커널이 막으면 `C:\Users\<you>\.wslconfig` 에
> `[wsl2]\nkernelCommandLine = ...` 조정이 필요할 수 있다(드묾).

---

## 4. 샌드박스 이미지 빌드 (레포 루트에서)

```bash
cd /mnt/c/Users/minwo/Downloads/HuggingMask
bash scripts/build_sandbox_images.sh
```
빌드되는 이미지:
- `huggingmask-b2-sandbox:local` — B-2 gVisor 커스텀 코드 샌드박스
- `weight-sandbox` — 피클 Path B 가중치 샌드박스(torch 포함, 수 분 소요)

**검증:** `docker image ls | grep -E "b2-sandbox|weight-sandbox"`

---

## 5. 전체 전제조건 검증

```bash
bash scripts/check_gvisor_setup.sh
```
모두 ✓ 면 다음 단계.

---

## 6. 서버를 WSL2 안에서 실행 (실제 실행 모드)

```bash
cd /mnt/c/Users/minwo/Downloads/HuggingMask
python3 -m venv .venv-linux && source .venv-linux/bin/activate
pip install -r requirements.txt

# 실제 샌드박스 실행 토글
export HUGGINGMASK_ENABLE_REAL_SANDBOX=1   # B-2 gVisor 실제 실행
export HUGGINGMASK_ENABLE_PATH_B=1         # 피클 Path B 실제 실행
export HUGGINGMASK_B2_IMAGE=huggingmask-b2-sandbox:local
export HUGGINGMASK_B2_RUNTIME=runsc

uvicorn proxy.app.main:app --port 8000
```

브라우저(Windows)에서 `http://localhost:8000/dashboard` →
🔬 모델 검사 → **gVisor 샌드박스 / 피클 Path B 단계가 실제 실행**되어
runsc evidence 와 함께 표시된다.

> 토글을 안 켜면(기본) 기존처럼 PENDING 으로 라우팅만 한다 — Windows 개발/데모 보존.

---

## 7. 빠른 단독 확인 (대시보드 없이 B-2만)

양유상 데모 러너로 runsc 실제 실행을 단독 확인할 수 있다:
```bash
python3 scripts/demo_b2_run.py \
  --image-ref huggingmask-b2-sandbox:local \
  --docker-runtime runsc \
  --evidence-dir evidence/sandbox
```
기대: `docker_runtime=runsc`, `runtime_verified=true`,
`decision=B2_POLICY_REVIEW_REQUIRED`, `deployable=false`.

---

## 트러블슈팅
| 증상 | 확인 |
|---|---|
| `docker info` 연결 불가 | Docker Desktop 실행 + WSL Integration 체크 / `sudo service docker start` |
| runtimes 에 runsc 없음 | `sudo runsc install` 후 docker 재시작 |
| runsc hello-world 실패 | WSL2 커널 버전 확인(`uname -r`), gVisor 최신 재설치 |
| 이미지 COPY 실패 | 빌드를 **레포 루트**에서 실행했는지(컨텍스트 `.`) |
| 권한 거부(docker) | `sudo usermod -aG docker $USER` 후 재로그인 |

전체 상태는 언제나: `bash scripts/check_gvisor_setup.sh`
