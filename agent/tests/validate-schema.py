#!/usr/bin/env python3
"""Validate one or more NDJSON files against the AI handoff JSON Schema."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import jsonschema


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        default=Path("docs/event-schema-v1.schema.json"),
    )
    arguments = parser.parse_args()
    schema = json.loads(arguments.schema.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    count = 0

    for path in arguments.inputs:
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                event = json.loads(line)
                errors = sorted(
                    validator.iter_errors(event), key=lambda error: list(error.path)
                )
                if errors:
                    raise SystemExit(
                        f"{path}:{line_number}: schema error: {errors[0].message}"
                    )
                count += 1
    if not count:
        raise SystemExit("no events to validate")
    print(f"event JSON schema validation passed ({count} events)")


if __name__ == "__main__":
    main()
