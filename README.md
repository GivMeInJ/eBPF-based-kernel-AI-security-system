# eBPF-based kernel AI security system

Linux 커널 이벤트를 eBPF로 수집하고, 서비스별 syscall 빈도를 기반으로 이상을
탐지하기 위한 프로젝트입니다.

현재 구현 범위는 다음과 같습니다.

- CO-RE eBPF 센서: 프로세스, 선택적 syscall, 파일, 네트워크 이벤트 수집
- Ring Buffer와 비동기 writer queue 기반 binary/NDJSON 출력
- `HEALTH` 이벤트를 통한 queue·ring-buffer 유실 상태 보고
- cgroup 또는 PID 범위 syscall 필터
- 정상 syscall 트레이스에서 IsolationForest 모델을 학습하는 파이프라인

```text
Linux workload
  -> eBPF host-events collector
  -> binary syscall stream
  -> ai/bin2traces.py
  -> ai/train.py
  -> model.pkl + syscall map + metadata
```

`agent/`에 커널 센서와 빌드 방법이 있으며, 모델 생성 절차는
[`agent/ai/README.md`](agent/ai/README.md)에 있습니다.

진행 중인 지도학습 버킷 모델의 집계 데이터·모델·평가 결과는
[`agent/ai/experiments/bucket-data9/`](agent/ai/experiments/bucket-data9/README.md)에 있습니다.
해당 실험의 기존 성능 수치는 라이브 탐지 성능으로 검증되지 않았으며,
시간 버킷 생성 방식에 알려진 불일치가 있습니다.

기본 파이프라인은 정상 데이터만으로 학습하는 이상 탐지 모델입니다. 별도의
지도학습 버킷 모델은 실험 단계이며, Wazuh 연동은 향후 통합 대상입니다.
