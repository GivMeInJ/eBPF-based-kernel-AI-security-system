#!/usr/bin/env python3
"""Validate protocol/port filtering for network events."""

import json
import sys


with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream if line.strip()]

network_events = [
    event for event in events if event.get("event_type", "").startswith("NETWORK_")
]
assert network_events
assert all(event.get("event_type") == "NETWORK_UDP_SEND" for event in network_events)
assert all(event.get("protocol") == 17 for event in network_events)
assert all(event.get("dst_port") == 9 for event in network_events)
print("network filter validation passed")
