# Benchmark result

측정 환경: Ubuntu 24.04 WSL2, kernel 6.18.33.1-microsoft-standard-WSL2.
이 결과는 보안 강화 코드가 반영된 기능·회귀 기준이며 실제 배포 서버의 성능 보장을
의미하지 않습니다.

| 항목 | 결과 |
|---|---:|
| UDP send syscall | 10,000 |
| workload 시간 | 155,733,575 ns |
| workload 처리율 | 64,212 events/s |
| 수집된 UDP 이벤트 | 10,000 |
| capture ratio | 1.000000 |
| writer queue drop | 0 |
| kernel Ring Buffer loss | 0 |
| Collector user CPU | 0.03 s |
| Collector system CPU | 0.10 s |
| 최대 RSS | 39,928 KiB |

Kernel BPF runtime stats (`trace_sendto_enter`, 10,000-event run):

| 항목 | 결과 |
|---|---:|
| 호출 수 | 10,004 |
| 누적 실행 시간 | 14,937,005 ns |
| 평균 실행 시간 | 1,493.10 ns/call |

측정 중에만 `kernel.bpf_stats_enabled=1`을 사용했으며 종료 후 기존 값 `0`으로
복원했습니다.

재측정 명령:

```bash
sudo bash bench/run-benchmark.sh .output/host-events 50000
sudo bash bench/profile-hooks.sh .output/host-events 100000
```
