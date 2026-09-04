eBPF-AI Guardian monitors Linux kernel events (execve, openat, connect) 
via eBPF kprobes and detects anomalous behavior using a two-stage AI pipeline: 
IsolationForest for fast pre-filtering and an LSTM model trained on the ADFA-LD 
syscall dataset for deep sequence analysis. Risk scores are computed as a weighted 
sum of rule-based and AI-inferred signals, then forwarded to a Wazuh SIEM dashboard 
for real-time visualization.
