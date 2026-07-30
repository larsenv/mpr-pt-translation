#!/usr/bin/env python3
"""Fill localized BMG entries that were left blank where English duplicates.

Several messages exist as consecutive duplicate ids -- grammatical gender and
number variants of one sentence. English and German write the same string into
every variant; French, Italian and Japanese filled the first and left the
duplicates blank. The game selects a variant by gender/number, so on those
languages it can land on an id that holds nothing at all.

The fill rule is deliberately narrow, because not every blank is a bug: an
entry is filled ONLY when English's text for that id is byte-identical to
English's text for the *previous* id. That is English explicitly marking the id
as a duplicate, so repeating the localized string is what the other languages
already do. Blanks that are not English-duplicates are left alone.

Usage: python3 tools/fill_variant_duplicates.py [msg_root] [--dry-run]
"""

import os
import re
import sys

# [^\S\n] is "whitespace but not newline" -- a plain \s* is greedy enough to
# swallow the line's own \n, which silently moves the filled text onto its own
# line and leaves the entry still blank.
ENTRY = re.compile(r"^([^\S\n]*)([0-9a-fA-F]+)([^\S\n]*=[^\S\n]*)(.*)$")
REFERENCE = "en_US"
dry_run = "--dry-run" in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith("-")]
root = args[0] if args else "usplat/00000005.app"


def parse(path):
    """Return (ordered ids, {id: text})."""
    order, text = [], {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ENTRY.match(line)
            if m:
                key = m.group(2).lower()
                order.append(key)
                text[key] = m.group(4).rstrip("\n")
    return order, text


def duplicate_ids(order, text):
    """Ids whose English text repeats the previous id's -- the fillable set."""
    dup = set()
    for i in range(1, len(order)):
        cur, prev = order[i], order[i - 1]
        if text.get(cur, "").strip() and text[cur].strip() == text.get(prev, "").strip():
            dup.add(cur)
    return dup


def fill(path, dup, ref_text):
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines(True)
    out, last, filled = [], None, []
    for line in lines:
        m = ENTRY.match(line.rstrip("\n"))
        if not m:
            out.append(line)
            continue
        key, body = m.group(2).lower(), m.group(4)
        if body.strip():
            last = body.rstrip("\n")
        elif key in dup and ref_text.get(key, "").strip() and last:
            line = "%s%s%s%s\n" % (m.group(1), m.group(2), m.group(3), last)
            filled.append((key, last))
        out.append(line)
    if filled and not dry_run:
        open(path, "w", encoding="utf-8").write("".join(out))
    return filled


ref_root = os.path.join(root, REFERENCE, "msg")
if not os.path.isdir(ref_root):
    print("Error: %s not found." % ref_root)
    sys.exit(1)

locales = sorted(d for d in os.listdir(root)
                 if os.path.isdir(os.path.join(root, d, "msg")) and d != REFERENCE)
total = 0
for name in sorted(os.listdir(ref_root)):
    if not name.endswith(".bmg.txt"):
        continue
    order, ref_text = parse(os.path.join(ref_root, name))
    dup = duplicate_ids(order, ref_text)
    if not dup:
        continue
    for loc in locales:
        path = os.path.join(root, loc, "msg", name)
        if not os.path.exists(path):
            continue
        filled = fill(path, dup, ref_text)
        if filled:
            total += len(filled)
            print("%-14s %-22s %d filled (ids: %s)"
                  % (loc, name, len(filled),
                     ", ".join(k for k, _ in filled[:8]) + (" ..." if len(filled) > 8 else "")))

print("\n%d entries filled%s." % (total, " (dry run)" if dry_run else ""))
