#!/usr/bin/env python3
"""Idempotently add insert-list entries to a dsh profile cordis.patch.yml.

Usage:
  patch_cordis.py <cordis.patch.yml> --plugins id[:name] [id[:name] ...]

The `- insert:` block in cordis.patch.yml is a top-level list entry whose
children are 2-space-indented `- id: X` / 4-space `name: 'dsh-X'` pairs.
Entries whose id already appears anywhere in the file are skipped.

If the file has no `- insert:` block, one is appended at the end.
"""

import os
import re
import sys


def main() -> None:
    args = sys.argv[1:]
    if len(args) < 3 or args[1] != "--plugins":
        sys.exit(__doc__)

    path = args[0]
    ids = []
    i = 2
    while i < len(args):
        ids.append(args[i])
        i += 1

    entries = []
    for tok in ids:
        if ":" in tok:
            pid, name = tok.split(":", 1)
        else:
            pid = tok
            name = f"dsh-{pid}"
        entries.append((pid, name))

    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    id_re = re.compile(r"^\s*-?\s*id:\s*([A-Za-z0-9_-]+)\s*$")
    present = {m.group(1) for ln in lines if (m := id_re.match(ln))}
    need = [e for e in entries if e[0] not in present]

    if not need:
        print(f"{path}: already up to date")
        return

    insert_idx = None
    for idx, ln in enumerate(lines):
        if re.match(r"^- insert:\s*$", ln):
            insert_idx = idx
            break

    new_lines = []
    if insert_idx is None:
        new_lines = list(lines)
        if new_lines and not new_lines[-1].endswith("\n"):
            new_lines[-1] += "\n"
        new_lines.append("- insert:\n")
        block = []
        for pid, name in need:
            block.append(f"  - id: {pid}\n")
            block.append(f"    name: '{name}'\n")
        new_lines.extend(block)
    else:
        j = insert_idx + 1
        while j < len(lines):
            ln = lines[j]
            if ln.strip() and not ln.startswith(" ") and not ln.startswith("\t") and not ln.startswith("#"):
                break
            j += 1
        block = []
        for pid, name in need:
            block.append(f"  - id: {pid}\n")
            block.append(f"    name: '{name}'\n")
        new_lines = lines[:j] + block + lines[j:]

    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
    os.replace(tmp, path)
    print(f"{path}: added {len(need)} insert entries: {', '.join(p for p, _ in need)}")


if __name__ == "__main__":
    main()