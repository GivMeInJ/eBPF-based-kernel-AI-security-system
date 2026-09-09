#!/usr/bin/env python3
"""Validate every concurrent connect/accept pair was delivered."""

import json
import sys


expected = 400
with open(sys.argv[1], encoding="utf-8") as stream:
    events = [json.loads(line) for line in stream if line.strip()]

connects = sum(event.get("event_type") == "NETWORK_CONNECT" for event in events)
accepts = sum(event.get("event_type") == "NETWORK_ACCEPT" for event in events)
if connects != expected or accepts != expected:
    raise SystemExit(f"expected {expected} pairs, got connect={connects} accept={accepts}")
print("concurrent connection validation passed")
