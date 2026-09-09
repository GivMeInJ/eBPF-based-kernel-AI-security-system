#!/usr/bin/env python3
"""Validate that a burst was bounded by the configured token bucket."""

import json
import sys


with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream if line.strip()]

udp_events = [
    event
    for event in events
    if event.get("event_type") == "NETWORK_UDP_SEND"
    and event.get("comm") == "python3"
]
if not 1 <= len(udp_events) <= 3:
    raise SystemExit(f"unexpected rate-limited event count: {len(udp_events)}")
print(f"network rate-limit validation passed ({len(udp_events)} emitted)")
