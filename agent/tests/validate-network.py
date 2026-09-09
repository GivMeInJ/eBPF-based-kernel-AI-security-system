#!/usr/bin/env python3
"""Validate the NDJSON produced by tests/network-workload.py."""

import json
import sys


required = {
    "NETWORK_BIND",
    "NETWORK_LISTEN",
    "NETWORK_CONNECT",
    "NETWORK_ACCEPT",
    "NETWORK_UDP_SEND",
    "NETWORK_TCP_STATE",
}

with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream if line.strip()]

python_events = [event for event in events if event.get("comm") == "python3"]
event_types = {event.get("event_type") for event in python_events}
event_types.update(
    event.get("event_type")
    for event in events
    if event.get("event_type") == "NETWORK_TCP_STATE"
)

missing = required - event_types
if missing:
    raise SystemExit(f"missing network events: {sorted(missing)}")

connect = next(
    event
    for event in python_events
    if event.get("event_type") == "NETWORK_CONNECT"
    and event.get("retval") == 0
)
assert connect["protocol"] == 6
assert connect["src_ip"] == "127.0.0.1"
assert connect["dst_ip"] == "127.0.0.1"
assert connect["src_port"] > 0 and connect["dst_port"] > 0

connections = [
    event
    for event in python_events
    if event.get("event_type") == "NETWORK_CONNECT"
    and event.get("retval") == 0
]
state_events = [
    event for event in events if event.get("event_type") == "NETWORK_TCP_STATE"
]
for connection in connections:
    cookie = connection.get("socket_cookie", 0)
    if cookie:
        assert any(event.get("socket_cookie") == cookie for event in state_events)

ipv6_connections = [event for event in connections if event.get("family") == 10]
if ipv6_connections:
    assert any(event.get("src_ip") == "::1" for event in ipv6_connections)
    assert any(event.get("dst_ip") == "::1" for event in ipv6_connections)

udp_events = [
    event
    for event in python_events
    if event.get("event_type") == "NETWORK_UDP_SEND"
]
assert any(event.get("protocol") == 17 for event in udp_events)
assert len(udp_events) >= 2
assert any(event.get("retval", 0) >= 7 for event in udp_events)

print("network event validation passed")
