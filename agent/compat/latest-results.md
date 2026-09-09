# Kernel compatibility result

- 실행 ID: `20260909T101613Z-cb02c9`
- 검증 방식: 동일 정적 loader를 disposable KVM VM에서 실제 load/attach
- 도구: bpfcompat v0.3.6 (`f1ba21fd4e098d483961e9e9355a51ae78273422`)
- 결과: 보안 강화가 반영된 최종 loader로 모든 필수 프로필 PASS

| 프로필 | 실제 부팅 커널 | 결과 |
|---|---|---|
| `ubuntu-22.04-5.15` | `5.15.0-190-generic` | PASS |
| `debian-12-6.1` | `6.1.0-52-cloud-amd64` | PASS |
| `ubuntu-24.04-6.8` | `6.8.0-138-generic` | PASS |

검증 명령은 각 VM에서 root로 다음 self-test를 실행했습니다.

```bash
host-events-static --self-test --no-file --network-events all \
  --format binary --output /tmp/ebpf-agent-self-test.bin
```

생성된 상세 JSON/Markdown 보고서는 각각 `local-report.json`과
`local-report.md`이며 git에서는 제외됩니다. CI 재검증은 저장소 루트의
`.github/workflows/ebpf-compatibility.yml`을 사용합니다.
