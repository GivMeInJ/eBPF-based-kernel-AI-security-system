# eBPF 호스트 이벤트 센서

AI 보안 에이전트의 커널 담당 파트를 독립적으로 검증하기 위한 libbpf
CO-RE 기반 센서입니다. 현재 범위는 프로세스, 선택적 syscall, 파일, 네트워크
연결 이벤트입니다.

## 구현된 이벤트

| 이벤트 | 연결 지점 | 의미 |
|---|---|---|
| `PROCESS_FORK` | `sched_process_fork` | 스레드/프로세스 생성 |
| `PROCESS_EXEC` | `sched_process_exec` | 성공한 프로그램 실행 |
| `PROCESS_EXIT` | `sched_process_exit` | 프로세스 리더 종료 |
| `SYSCALL_ENTER` | `raw_tracepoint/sys_enter` | 선택 대상의 syscall 진입 |
| `SYSCALL_EXIT` | `raw_tracepoint/sys_exit` | syscall ID와 반환값 |
| `FILE_OPEN` | `lsm.s/file_open` | 파일 열기 보안 검사 시점 |
| `FILE_UNLINK` | `lsm/inode_unlink` | 파일 삭제 보안 검사 시점 |
| `NETWORK_CONNECT` | `sys_enter/exit_connect` | IPv4/IPv6 연결 결과와 양 끝점 |
| `NETWORK_BIND` | `sys_enter/exit_bind` | 로컬 주소와 Port 바인딩 결과 |
| `NETWORK_LISTEN` | `sys_enter/exit_listen` | 서버 listen 및 backlog |
| `NETWORK_ACCEPT` | `sys_enter/exit_accept(4)` | 성공한 수신 연결의 양 끝점 |
| `NETWORK_UDP_SEND` | `sys_enter/exit_sendto/sendmsg` | 연결형·비연결형 UDP 전송 결과 |
| `NETWORK_TCP_STATE` | `sock/inet_sock_set_state` | TCP 상태 전이와 socket cookie |
| `HEALTH` | 사용자 공간 Collector | Queue/Ring Buffer 유실·필터·rate-limit 누계 |

파일 센서는 관측 전용입니다. 기존 LSM 반환값을 그대로 반환하므로 접근을 허용하거나
차단하지 않습니다. `FILE_OPEN`은 최종 시스템 콜 성공 결과가 아니라 LSM 검사 시점의
접근 시도라는 점도 데이터 소비자가 구분해야 합니다.

## 구조

```text
include/agent_events.h       공통 binary ABI와 설정 구조체
src/bpf/host_events.bpf.c   CO-RE 커널 센서
server.c                    네트워크 syscall·cgroup·TCP 상태 센서
src/user/host_events.c      로드·출력 검증용 최소 Collector
Makefile                    vmlinux.h, BPF object, skeleton 생성
```

커널 센서가 버전과 크기가 포함된 `agent_event`를 Ring Buffer로 보내고, Collector가
이를 NDJSON으로 변환합니다. 네트워크 이벤트는 필요한 payload 길이만 전송하며,
Collector 부분은 실제 에이전트의 메시지 큐 또는 API 어댑터로 교체할 수 있습니다.
syscall 진입/종료 상태는 Task Storage, socket 관측 상태는 Socket Storage에 저장되어
task/socket 종료 시 자동으로 정리됩니다.

## 요구사항

- Linux 실행 환경(x86-64 또는 arm64 권장)
- BTF가 노출된 커널: `/sys/kernel/btf/vmlinux`
- clang/LLVM, bpftool, libbpf, libelf, zlib
- 파일 센서 사용 시 `CONFIG_BPF_LSM=y` 및 활성 LSM 목록에 `bpf`
- socket cookie와 커널이 확인한 목적지 보강 시 cgroup v2 마운트

Ubuntu/Debian 계열의 예시 설치 명령입니다.

```bash
sudo apt-get update
sudo apt-get install -y clang llvm gcc make pkg-config \
  bpftool libbpf-dev libelf-dev zlib1g-dev
```

이 프로젝트의 호스트가 Windows이더라도 eBPF 빌드와 실행은 Linux/WSL2 또는
Linux VM에서 진행해야 합니다.

## 빌드

```bash
cd ebpf-agent
make
```

생성 결과:

```text
.output/vmlinux.h
.output/host_events.bpf.o
.output/host_events.skel.h
.output/server.bpf.o
.output/server.skel.h
.output/host-events
.output/host-events-static
```

호환성 VM에서 실행할 정적 loader는 `make static`으로 만듭니다.

## 실행

기본 실행은 프로세스·네트워크 이벤트와, 지원되는 경우 파일 이벤트를 NDJSON으로
출력합니다.

```bash
sudo .output/host-events
sudo .output/host-events --output events.ndjson
```

파일 출력은 전체 경로의 symbolic link를 거부하고, regular file을 `0600`으로 제한하며,
기존 내용을 지우지 않고 append합니다. eBPF load/attach와 출력 파일 준비가 끝나면 root로
실행한 Collector는 기본적으로 UID/GID `65534:65534`로 권한을 낮춥니다. 전용 서비스
계정을 사용하려면 `--run-as UID:GID`, 디버깅 목적으로 권한을 유지해야 할 때만
`--retain-privileges`를 명시합니다.

경로 출력은 기본적으로 regular file만 허용합니다. 성능 시험의 `/dev/null`이나 검증용
FIFO처럼 신뢰된 special file이 꼭 필요한 경우에만 `--allow-special-output`을 추가합니다.

WSL의 `/mnt/c` 같은 DrvFS에서 group/other 권한 제거가 실제로 반영되지 않으면 Collector는
민감 로그 출력을 거부합니다. 이 경우 `/var/lib/ebpf-agent`처럼 WSL/Linux 파일시스템의
보호된 디렉터리를 사용합니다.

고속 binary frame 출력과 NDJSON 변환:

```bash
sudo .output/host-events --no-file --format binary --output events.bin
python3 tools/decode-events.py events.bin > events.ndjson
```

BPF LSM을 사용할 수 없는 환경에서는 파일 센서를 끕니다.

```bash
sudo .output/host-events --no-file --output events.ndjson
```

syscall 이벤트는 양이 많으므로 명시적으로 활성화하고 반드시 PID 또는 cgroup
범위를 지정해야 합니다. 가능한 경우 PID보다 cgroup을 지정해 프로세스 트리
전체를 제한하는 것이 좋습니다. Collector 자신의 TGID는 피드백 루프 방지를 위해
커널 필터에서 자동 제외됩니다. PID namespace 환경에서도 필터가 일치하도록
Collector가 `/proc/self/ns/pid`의 device/inode를 커널 설정 Map에 전달합니다.

```bash
sudo .output/host-events --syscalls --target-pid 4210
sudo .output/host-events --syscalls --target-cgroup 12345678
sudo .output/host-events --syscalls-enter-only --target-cgroup 12345678
```

`--syscalls-enter-only` emits only `SYSCALL_ENTER`. Use it for the AI pipeline,
which builds syscall-frequency features and does not use return values. It cuts
high-volume syscall output roughly in half.

## AI model pipeline

`ai/` contains the normal-data collection conversion and training tools. It
keeps collector data, the syscall-ID map, model metadata, and the trained model
as one deployable set. See [`ai/README.md`](ai/README.md).

네트워크 Port·protocol 필터와 Ring Buffer 크기를 지정할 수 있습니다.

```bash
sudo .output/host-events --no-file \
  --network-protocol tcp --network-port 443 \
  --ringbuf-bytes 1048576 --output events.ndjson
```

필요한 hook만 선택적으로 로드할 수 있습니다. 목록은 `connect`, `bind`, `listen`,
`accept`, `udp`, `tcp-state`이며 쉼표로 구분합니다.
고빈도 `tcp-state`는 기본 비활성화되어 있으며 명시적으로 선택해야 합니다.

```bash
sudo .output/host-events --no-file \
  --network-events connect,accept,tcp-state
```

cgroup·TGID·이벤트 종류·protocol·관련 Port별 O(1) token-bucket 제한을 설정할 수
있습니다. 필터 검사가 끝난 유효 이벤트만 quota를 소비합니다.

```bash
sudo .output/host-events --no-file \
  --network-rate 1000 --network-burst 2000
```

Writer는 기본 4096-slot bounded queue를 사용합니다. 1/8은 exec, unlink, 주요 네트워크
이벤트와 `HEALTH`용으로 예약됩니다. 출력이 느려 큐가 가득 차면 커널 polling을 막지
않고 저우선순위 이벤트부터 버리며 `writer queue dropped`로 집계합니다.

```bash
sudo .output/host-events --queue-capacity 16384 --format binary \
  --output events.bin
```

기본적으로 `/sys/fs/cgroup`에 connect/bind/sendmsg 보강 hook을 연결합니다. 사용할
수 없거나 구형 커널에서 tracepoint fallback만 사용하려면 다음과 같이 실행합니다.

```bash
sudo .output/host-events --no-file --no-cgroup-hooks
sudo .output/host-events --cgroup-path /sys/fs/cgroup/my-service
```

Collector는 1초마다 `HEALTH` 이벤트를 출력 스트림에 넣어 Queue drop, Ring Buffer
loss, 필터 및 rate-limit 누계를 AI 계층이 실시간으로 확인하게 합니다. 종료 시에는
동일 통계와 이벤트 타입별 수신량도 표준 오류에 출력됩니다.

## 빠른 확인

첫 번째 터미널:

```bash
sudo .output/host-events --no-file --output /tmp/host-events.ndjson
```

두 번째 터미널:

```bash
/bin/sh -c '/usr/bin/true'
python3 -c 'import socket; s=socket.socket(); s.connect_ex(("127.0.0.1", 9))'
```

첫 번째 터미널에서 `Ctrl+C`로 종료한 다음 확인합니다.

```bash
grep -E 'PROCESS_(FORK|EXEC|EXIT)|NETWORK_CONNECT' /tmp/host-events.ndjson
```

자동 검증:

```bash
sudo bash tests/runtime-smoke.sh
sudo bash tests/network-smoke.sh
sudo bash tests/filter-smoke.sh
sudo bash tests/rate-smoke.sh
sudo bash tests/binary-smoke.sh
sudo bash tests/backpressure-smoke.sh
sudo bash tests/nonblocking-smoke.sh
sudo bash tests/rate-map-smoke.sh
sudo bash tests/fallback-smoke.sh
sudo bash tests/concurrency-smoke.sh
sudo bash tests/security-smoke.sh
```

성능 측정:

```bash
sudo bash bench/run-benchmark.sh .output/host-events 50000
sudo bash bench/profile-hooks.sh .output/host-events 100000
```

출력에는 workload events/s, Collector CPU/RSS, capture ratio, queue drop 및 Ring Buffer
유실이 포함됩니다. 최근 기준 측정은 `bench/latest-results.md`에 기록됩니다.

## 커널 호환성

동일 정적 loader의 real load/attach self-test가 다음 VM에서 통과했습니다.

| 배포판 | 실제 커널 | 결과 |
|---|---|---|
| Ubuntu 22.04 | 5.15.0-190-generic | PASS |
| Debian 12 | 6.1.0-52-cloud-amd64 | PASS |
| Ubuntu 24.04 | 6.8.0-138-generic | PASS |

매트릭스는 `compat/kernel-matrix.yaml`, 로컬 실행기는
`compat/run-local-matrix.sh`, CI 설정은 `.github/workflows/ebpf-compatibility.yml`에
있습니다. 최근 실행 결과는 `compat/latest-results.md`에 기록되어 있습니다.
빠른 현재-kernel 검사는 다음과 같습니다.

```bash
sudo .output/host-events-static --self-test --no-file \
  --network-events all --format binary --output /tmp/self-test.bin
```

호환성 도구가 생성하는 SSH·artifact signing 개인키와 실행 작업은 저장소가 아닌
`${XDG_CACHE_HOME:-$HOME/.cache}/ebpf-agent/bpfcompat-work`에 둡니다.
`EBPF_AGENT_VM_WORKDIR`로 별도 보호 디렉터리를 지정할 수 있습니다. `vm/cache/`와 일반
개인키 패턴도 `.gitignore`에서 제외되지만, 캐시 폴더를 수동 업로드하면 안 됩니다.

고정 ABI는 `docs/event-schema-v1.md`를 기준으로 합니다.

## 현재 제한사항

- syscall 이벤트는 번호와 반환값만 수집하며 syscall별 인자를 해석하지 않습니다.
- 이벤트에는 호스트 PID/TGID와 Collector PID namespace 기준 PID/TGID가 함께
  포함됩니다. PPID는 현재 호스트 기준 값입니다.
- `--target-pid`는 해당 TGID만 추적하며 이후 생성된 자식 프로세스를 자동으로
  포함하지 않습니다. 프로세스 트리 추적은 cgroup 필터가 더 적합합니다.
- `FILE_UNLINK` 경로는 전체 경로가 아니라 dentry의 마지막 이름만 제공하므로
  `AGENT_FLAG_PARTIAL_PATH`가 설정됩니다.
- 실패하거나 진행 중인 연결은 source 주소가 결정되지 않을 수 있으며 이때
  `src_ip`는 `null`이고 `AGENT_FLAG_NETWORK_SOURCE_VALID`가 설정되지 않습니다.
- 비연결 UDP는 로컬 Port만 자동 할당되고 로컬 IP는 socket에 남지 않을 수 있으므로
  `src_port`는 존재하면서 `src_ip`가 `null`일 수 있습니다.
- `sendmsg`는 native ABI를 처리하며 compat ABI 및 `sendmmsg`는 아직 포함하지 않습니다.
  iovec 순회는 하지 않으며 실제 전송량은 `retval`을 사용합니다.
- TCP 상태 callback은 항상 socket 소유 프로세스 문맥에서 실행되지 않으므로
  `AGENT_FLAG_NETWORK_PROCESS_UNCERTAIN`이 설정됩니다. socket cookie로 연결 이벤트와
  결합해야 합니다. 기본적으로 cgroup SockOps+Socket Storage를 사용하고, cgroup hook이
  없으면 `inet_sock_set_state` tracepoint로 전환됩니다. PID/cgroup 대상 필터 사용 시
  TCP 상태 이벤트는 비활성화됩니다.
- `--target-cgroup`은 정확히 같은 cgroup ID만 비교합니다. cgroup hook의 하위 계층
  상속과는 별개의 수집 후 필터입니다.
- 커널 monotonic timestamp를 사용합니다. wall-clock 변환은 사용자 공간 통합
  계층에서 수행해야 합니다.
- Ring Buffer 유실 카운터는 커널에서 reserve에 실패한 이벤트만 포함합니다.
- 보안 관련 이벤트도 자원 한계에서는 유실될 수 있으므로 AI 계층은 `HEALTH` 이벤트의
  누계가 증가하면 해당 시간 구간의 판정 신뢰도를 낮추거나 경보해야 합니다.

## 통합 인터페이스

모든 센서와 AI 입력 어댑터는 다음 규칙을 유지해야 합니다.

- `header.version`과 `header.size`를 먼저 검증
- 모르는 이벤트 타입은 에이전트를 종료하지 않고 건너뜀
- 스키마 v1의 기존 필드 의미와 크기를 변경하지 않음
- `header.flags`를 보존해 경로 누락·부분 경로를 AI 입력에서 구분
- 네트워크 주소는 network byte order의 바이트 배열, Port는 host byte order로 처리
- `retval=-EINPROGRESS`는 비동기 연결 진행 상태이며 즉시 실패로 분류하지 않음
- TCP 상태 이벤트의 PID보다 `socket_cookie` 상관관계를 우선 사용
- `src_ip=null`과 `0.0.0.0`을 구분하고 address validity flag를 보존
- 고용량 syscall 수집은 기본 비활성화하고 PID/cgroup 범위를 지정
- `HEALTH`의 유실·필터·rate-limit 누계를 모델 입력 품질 지표로 사용

AI팀 전달 패키지는 다음 명령으로 재현할 수 있습니다.

```bash
make static
bash tools/build-ai-handoff.sh
```

`dist/ai-handoff-schema-v1-20260909.{tar.gz,zip}`과 검증된 동일 내용의 디렉터리가
생성되며 `.ARCHIVE_SHA256SUMS`로 압축 파일을 검증할 수 있습니다. 상세 인수 규칙은
[`docs/ai-handoff-v1.md`](docs/ai-handoff-v1.md)를
기준으로 합니다. `dist/`는 Git 저장소에 넣지 말고 GitHub Release asset 또는 보호된
내부 파일 전달 채널로 공유합니다.

## 시간복잡도

커널 hot path에는 Map 순회나 입력 크기에 비례하는 반복문이 없습니다.

- 설정·Task Storage·Socket Storage 조회: O(1)
- Port/protocol/PID/cgroup 필터: O(1)
- rate limit: 최대 4회 CAS로 제한된 O(1)
- IPv4/IPv6 복사: 고정 길이 O(1)
- Ring Buffer 제출: 이벤트당 O(1)

전체 비용은 O(수집 이벤트 수)이며, 선택적 autoload와 조기 필터가 이벤트 수 자체를
줄입니다.
