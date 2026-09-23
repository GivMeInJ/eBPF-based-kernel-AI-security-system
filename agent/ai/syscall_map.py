#!/usr/bin/env python3
"""Build the x86_64 syscall-number to feature-ID map used by the AI pipeline."""
import argparse
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("adfa_map", type=Path,
                        help="OSCAIR_Syscall_Map.txt from ADFA-LD-with-OSCAIR")
    parser.add_argument("--output", type=Path,
                        default=Path("syscall_map_x86_64.json"))
    args = parser.parse_args()

    names = {}
    for line in args.adfa_map.read_text().splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].isdigit():
            names.setdefault(parts[2], int(parts[0]))

    output = subprocess.run(["ausyscall", "--dump"], check=True,
                            capture_output=True, text=True).stdout
    mapping, added, next_id = {}, [], 1083
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        number, name = int(parts[0]), parts[1]
        feature_id = names.get(name, names.get(f"{name}64"))
        if feature_id is None:
            feature_id = next_id
            added.append({"nr": number, "name": name, "feature_id": feature_id})
            next_id += 1
        mapping[number] = feature_id

    args.output.write_text(json.dumps({"vocab_size": next_id,
                                        "nr_to_feature_id": mapping,
                                        "newly_assigned": added}, indent=2) + "\n")
    print(f"wrote {args.output}: VOCAB_SIZE={next_id}, new IDs={len(added)}")


if __name__ == "__main__":
    main()
