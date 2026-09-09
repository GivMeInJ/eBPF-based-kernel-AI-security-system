# eBPF 에이전트 검증 보고서

> 검증일: 2026-09-09  
> 결론: **PASS (보안 회귀시험 포함)**  
> 검증 범위: 빌드, verifier/load/attach, 프로세스, 시스템콜, 파일 BPF LSM,
> 네트워크, 직렬화, 필터, rate limit, 동시성, fallback, backpressure

## 1. 최종 판정

현재 구현은 검증한 Linux x86-64 환경에서 정상적으로 빌드되고, eBPF verifier를
통과하며, 각 프로그램이 실제 커널 hook에 연결된다. 생성한 이벤트는 Ring Buffer와
bounded writer queue를 거쳐 NDJSON 또는 binary frame으로 정상 기록된다.

추가 보안 감사에서 발견한 privileged output symlink, world-readable 출력, oversized
binary frame, 타입별 짧은 frame, 잘못된 UTF-8, rate-limit bucket starvation 위험을
수정하고 공격 입력 기반 회귀시험을 통과했다.

파일 센서까지 포함한 실부팅 시험에서 다음 결과를 확인했다.

```text
active LSMs: capability,bpf
FILE_OPEN        received=4 lost=0
FILE_UNLINK      received=1 lost=0
HEALTH           received=3 lost=0
EBPF_LSM_FILE_TEST_PASS
```

따라서 `FILE_OPEN`과 `FILE_UNLINK`는 단순 컴파일 확인이 아니라, BPF LSM이 활성화된
커널에서 실제 파일 열기·생성·삭제 동작을 발생시켜 end-to-end로 검증했다.

## 2. 검증 환경

### 일반 회귀·성능 시험

- Ubuntu 24.04 WSL2
- kernel `6.18.33.1-microsoft-standard-WSL2`
- eBPF C + C/libbpf
- root 권한으로 load/attach 및 workload 실행

### 파일 BPF LSM 시험

- QEMU x86-64 실제 부팅
- Linux `6.6.145`
- boot parameter `lsm=bpf`
- initramfs에서 `tracefs`, `securityfs`, `proc`, `sysfs` 직접 마운트
- 정적 Collector `.output/host-events-static` 사용

필수 커널 설정을 확인했다.

```text
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_LSM=y
CONFIG_CGROUP_BPF=y
CONFIG_SECURITYFS=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS=y
CONFIG_LSM="bpf"
```

## 3. 빌드 검증

실행 명령:

```bash
make check static
```

결과:

```text
Build check passed: .output/host-events
make: Nothing to be done for 'static'.
```

- BPF object 생성 성공
- libbpf skeleton 생성 성공
- 사용자 공간 Collector 경고 없는 빌드 성공
- 정적 compatibility loader 생성 확인

## 4. 기능 회귀 시험

다음 11개 시험을 동일 소스와 실행 파일로 다시 수행했다.

| 시험 | 검증 대상 | 결과 |
|---|---|---:|
| `runtime-smoke.sh` | process fork/exec/exit, 대상 PID syscall enter/exit | PASS |
| `network-smoke.sh` | IPv4/IPv6 connect, bind, listen, accept, UDP, TCP state | PASS |
| `binary-smoke.sh` | binary frame encode/decode 및 schema | PASS |
| `filter-smoke.sh` | 이벤트·protocol·Port 필터 | PASS |
| `rate-smoke.sh` | token 간격 기반 rate limit | PASS |
| `rate-map-smoke.sh` | 작은 LRU Map 포화 동작 | PASS |
| `nonblocking-smoke.sh` | 비차단 connect의 `-EINPROGRESS` 보존 | PASS |
| `concurrency-smoke.sh` | 8 thread 동시 connect/accept | PASS |
| `fallback-smoke.sh` | cgroup/SockOps 미사용 tracepoint 경로 | PASS |
| `backpressure-smoke.sh` | 느린 sink와 bounded queue | PASS |
| `security-smoke.sh` | symlink·권한·UTF-8·악성 binary frame | PASS |

### 프로세스·시스템콜

- `PROCESS_EXEC` 및 프로세스 생명주기 이벤트 확인
- 대상 PID의 `SYSCALL_ENTER` 1,154건과 `SYSCALL_EXIT` 1,154건 수집
- 시스템콜 진입·반환 쌍의 kernel loss 0

### 네트워크

- connect, bind, listen, accept, UDP send 및 TCP state 이벤트 확인
- `map_update_failed=0`
- `socket_read_failed=0`
- `ringbuf_lost=0`
- `user_read_failed=0`
- 비차단 connect 반환값 `-EINPROGRESS` 보존 확인

### 필터와 rate limit

- 필터 대상이 아닌 이벤트 10건이 kernel 단계에서 제외됨
- UDP 100건 burst에서 2건 방출, 98건 rate limit 처리
- rate-limit Map capacity를 2로 제한한 포화 시험에서도 Map update 실패 0

### 동시성

8개 thread가 동시에 연결을 생성한 시험 결과:

```text
NETWORK_CONNECT received=400 lost=0
NETWORK_ACCEPT  received=400 lost=0
writer queue dropped=0
ringbuf_lost=0
```

### Backpressure

queue capacity 8, UDP 10,000건, 지연 FIFO reader 조건의 결과:

```text
writer queue dropped=9699
writer priority dropped=1
NETWORK_UDP_SEND received=303 lost=0
ringbuf_lost=0
```

이 시험의 queue drop은 실패가 아니다. 느린 출력 sink가 kernel event polling을 막거나
메모리를 무한히 증가시키지 않고, 정해진 bounded queue 정책에 따라 사용자 공간에서
명시적으로 drop하고 계수하는지 확인한 결과다. 중요 이벤트용 Queue 예약 공간과
`HEALTH.writer_queue_dropped > 0`이 binary 출력에서도 전달되는 것을 함께 확인했다.

## 5. 보안 회귀 시험

[`tests/security-smoke.sh`](tests/security-smoke.sh)는 다음 공격 조건을 자동 검증한다.

- root Collector의 symlink 출력 거부 및 대상 파일 보존
- 기존 로그 append와 regular file mode `0600`
- 1 GiB로 위조한 frame 길이를 읽기 전에 거부
- 88-byte 가짜 `FILE_OPEN` record 거부
- `0xff`가 포함된 process comm도 유효한 UTF-8 NDJSON으로 직렬화
- 종료 전 `HEALTH` 이벤트 생성
- 기본 강등, custom `--run-as`, 명시적 `--retain-privileges` 동작
- 호환성 도구의 work/private-key 경로를 저장소 밖 사용자 cache로 분리

Collector는 BPF load/attach 후 기본적으로 UID/GID `65534:65534`로 권한을 낮추며,
보안 회귀시험을 포함한 전체 기능시험이 이 상태에서 통과했다.
기존 VM 실행 캐시에 남아 있던 일회성 개인키 10개도 제거했다.

직접 NDJSON과 binary decoder 출력은 동일한
[`event-schema-v1.schema.json`](docs/event-schema-v1.schema.json)으로 검증했다.
프로세스·syscall 2,320건, 네트워크 42건, binary decode 39건이 모두 통과했다.
AI handoff의 19개 fixture와 tar.gz·zip 재해제 결과도 bundle validator를 통과했다.

## 6. 파일 BPF LSM 실부팅 시험

시험용 init은 [`tests/lsm-qemu-init`](tests/lsm-qemu-init)이다. 다음 순서로 검증한다.

1. `tracefs`와 `securityfs`를 마운트한다.
2. Collector를 파일 센서 활성 상태로 시작한다.
3. `/etc/passwd`를 연다.
4. `/tmp/ebpf-lsm-validation`을 생성하고 삭제한다.
5. Collector를 정상 종료한다.
6. NDJSON에서 `FILE_OPEN`과 `FILE_UNLINK`를 각각 검사한다.

Linux 6.6.145 QEMU 출력:

```text
active LSMs:
capability,bpf
host event sensors started (syscalls=off files=on target_pid=0)
writer queue dropped=0
writer priority dropped=0
FILE_OPEN        received=4 lost=0
FILE_UNLINK      received=1 lost=0
HEALTH           received=3 lost=0
EBPF_LSM_FILE_TEST_PASS
```

QEMU assertion은 `HEALTH` record의 `uid=65534`, `gid=65534`도 검사하므로 BPF LSM
attach 후 권한 강등 상태에서도 파일 센서와 출력 파이프라인이 유지됨을 확인한다.

확인된 경로는 다음과 같다.

```text
file operation
  -> Linux Security Module hook
  -> BPF LSM program
  -> Ring Buffer
  -> Collector queue
  -> NDJSON serializer
  -> FILE_OPEN / FILE_UNLINK assertion
```

## 7. 커널 호환성 시험

정적 loader로 다음 배포판 커널에서도 CO-RE relocation, Map 생성, verifier load 및
attach를 확인했다. 이 일반 매트릭스는 배포판별 BPF LSM 활성 상태 차이를 배제하기
위해 `--no-file`로 수행했으며, 파일 센서는 위 Linux 6.6.145 전용 시험으로 보완했다.

| 환경 | 커널 | 범위 | 결과 |
|---|---|---|---:|
| Ubuntu 22.04 VM | `5.15.0-190-generic` | process/syscall/network load·attach | PASS |
| Debian 12 VM | `6.1.0-52-cloud-amd64` | process/syscall/network load·attach | PASS |
| Custom QEMU | `6.6.145` | BPF LSM file open/unlink end-to-end | PASS |
| Ubuntu 24.04 VM | `6.8.0-138-generic` | process/syscall/network load·attach | PASS |

보안 수정 후 최종 정적 loader로 같은 세 배포판 매트릭스를 재실행했으며 모두 PASS였다.

## 8. 성능 기준값

기존 WSL2 기준 성능 시험 결과도 함께 확인했다.

| 항목 | 결과 |
|---|---:|
| UDP 이벤트 생성 | 10,000 |
| 수집 이벤트 | 10,000 |
| capture ratio | 1.000000 |
| workload 처리율 | 64,212 events/s |
| writer queue drop | 0 |
| kernel Ring Buffer loss | 0 |
| `trace_sendto_enter` 평균 | 1,493.10 ns/call |

이는 해당 시험 환경의 회귀 기준값이며, 실제 배포 장비의 처리량 보장은 아니다.

## 9. 판정과 운영 조건

검증 범위 안에서 기능 오류나 verifier 거부, 예상하지 않은 이벤트 유실은 발견되지
않았다. 다만 파일 센서를 운영하려면 배포 대상 커널에서 다음 조건이 충족돼야 한다.

- `CONFIG_BPF_LSM=y`
- boot 시 활성 LSM 목록에 `bpf` 포함
- BTF 사용 가능
- BPF trampoline을 지원하는 ftrace 설정
- root 또는 필요한 BPF/perf 관련 capability

또한 `FILE_OPEN`은 최종 `open(2)` 성공 통지가 아니라 LSM 검사 시점의 접근 이벤트이며,
`FILE_UNLINK`의 이름은 hook 특성상 전체 경로가 아닌 basename일 수 있다. 이 의미는 AI
입력 schema와 탐지 규칙에서도 그대로 유지해야 한다.
