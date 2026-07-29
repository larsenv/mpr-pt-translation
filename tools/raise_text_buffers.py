#!/usr/bin/env python3
"""Raise textBufBytes on every text pane in the dialog BRLYTs.

nw4r's lyt::TextBox allocates its string buffer from the layout's
`textBufBytes` field and SetString() silently truncates to that buffer -- it
never reallocates.  The dialog layouts were authored with buffers just big
enough for the designers' placeholder text (text_up is 12 bytes = 5 chars,
the arrow labels are 14 bytes = 7 chars), so any longer localized string
coming from BMG gets clipped.  Several of the second-page panes
(next_text_down, next_s01_c..next_s04_c) ship with a buffer of 0, which means
SetString on them stores nothing at all.

Only the 2-byte textBufBytes field is touched.  textStrBytes, textStrOffset
and the inline string data are left alone, so the file length and every
section offset stay identical -- this is a pure in-place field edit.

Usage: python3 tools/raise_text_buffers.py [blyt_dir] [--min BYTES] [--all]
"""

import os
import struct
import sys

DEFAULT_MIN = 128           # bytes -> 63 UTF-16 characters plus terminator
DIALOG_PREFIX = "dlg_"

args = [a for a in sys.argv[1:] if not a.startswith("-")]
blyt_dir = args[0] if args else "usplat/00000004.app/ui/arc/blyt"
minimum = DEFAULT_MIN
if "--min" in sys.argv:
    minimum = int(sys.argv[sys.argv.index("--min") + 1])
every_layout = "--all" in sys.argv

if minimum % 2:
    print("Error: --min must be even (UTF-16).")
    sys.exit(1)
if not os.path.isdir(blyt_dir):
    print(f"Error: {blyt_dir} is not a directory.")
    sys.exit(1)


def raise_buffers(path, minimum):
    """Return (panes_changed, terminated, total_panes) after rewriting in place.

    Raising textBufBytes on its own is NOT safe.  Most of these panes store
    their placeholder string filling textStrBytes exactly, with no NUL pair at
    the end -- dlg_b4's right_c is 14 bytes holding 7 characters.  With a
    14-byte buffer the copy was bounded by the buffer; with a bigger buffer
    SetString runs past the string into whatever follows in the section until
    it happens to find a NUL pair, which is how the enlarged buffers crashed
    the game at boot.

    So before raising anything, force the final UTF-16 unit of each stored
    string to 0x0000.  That keeps the terminator inside the original span --
    no offsets move -- at the cost of one placeholder character, which the
    game overwrites from BMG anyway.
    """
    d = bytearray(open(path, "rb").read())
    off, changed, terminated, total = 0x10, 0, 0, 0
    while off + 8 <= len(d):
        magic = bytes(d[off:off + 4])
        size = struct.unpack(">I", d[off + 4:off + 8])[0]
        if size < 8 or off + size > len(d):
            break
        if magic == b"txt1":
            total += 1
            str_bytes = struct.unpack(">H", d[off + 0x4E:off + 0x50])[0]
            str_off = struct.unpack(">I", d[off + 0x58:off + 0x5C])[0]
            if str_bytes >= 2 and str_off:
                end = off + str_off + str_bytes
                if bytes(d[end - 2:end]) != b"\x00\x00":
                    d[end - 2:end] = b"\x00\x00"
                    terminated += 1
            buf_off = off + 0x4C
            if struct.unpack(">H", d[buf_off:buf_off + 2])[0] < minimum:
                struct.pack_into(">H", d, buf_off, minimum)
                changed += 1
        off += size
    if changed or terminated:
        open(path, "wb").write(d)
    return changed, terminated, total


targets = sorted(
    f for f in os.listdir(blyt_dir)
    if f.endswith(".brlyt") and (every_layout or f.startswith(DIALOG_PREFIX))
)
if not targets:
    print(f"Error: no matching .brlyt found in {blyt_dir}.")
    sys.exit(1)

grand = 0
for f in targets:
    changed, terminated, total = raise_buffers(os.path.join(blyt_dir, f), minimum)
    grand += changed
    print(f"{f:<18} {changed}/{total} panes raised to {minimum} bytes, "
          f"{terminated} strings NUL-terminated")

print(f"\n{grand} panes updated across {len(targets)} layouts; file sizes unchanged.")
