#!/usr/bin/env python3
"""Write full strings into BRLYT text panes, growing the section to fit.

The localized dialog layouts ship with their strings clipped to whatever fitted
the original textBufBytes -- dlg_fr's text_up is a 12-byte buffer holding
"Pannea", six characters of "Panneau d'affichage".  Raising the buffer does not
bring the missing characters back; the rest of the string is simply not in the
file.  Writing a longer string means growing the txt1 section, which is safe:
textStrOffset is relative to its own section, the string sits at the end of the
section, and nothing in a BRLYT refers to another section by absolute offset.
Only the section size and the file size in the header need fixing up.

Strings live in STRINGS below.  Panes not listed are left untouched.

Usage: python3 tools/set_layout_text.py [blyt_dir] [--dry-run]
"""

import os
import struct
import sys

# layout -> pane -> string.  text_up is the dialog title; next_text_up is the
# same label on the second page and ships untranslated ("BBS") in every layout.
STRINGS = {
    "dlg_fr.brlyt": {
        "text_up": "Panneau d'affichage",
        "next_text_up": "Panneau d'affichage",
    },
    # (font sizes for these live in FONTS below)
    "dlg_de.brlyt": {
        "text_up": "Schwarzes Brett",
        "next_text_up": "Schwarzes Brett",
    },
    "dlg_it.brlyt": {
        "text_up": "Bacheca",
        "next_text_up": "Bacheca",
    },
    # dlg_es shipped untranslated upstream -- its text_up was byte-identical to
    # dlg_b4's "BBS".  The term matches es_ES/msg/pokemonfarm.bmg (ids 4f, c3,
    # ea, 23e, 23f), which already reads "Tablon de anuncios".
    "dlg_es.brlyt": {
        "text_up": "Tablón de anuncios",
        "next_text_up": "Tablón de anuncios",
    },
    # dlg_en / dlg_b4 keep "BBS", which already fits.
}

# layout -> pane -> (fontSizeX, fontSizeY).  Every dialog layout ships with
# dlg_b4's metrics -- 28.80 x 34.20 in a 320px pane -- because the localized
# layouts are dlg_b4 with the strings swapped and nothing else touched.  There
# is no auto-fit in nw4r: a string wider than the pane wraps, which is why
# "Panneau d'affichage" spilled its final "e" onto a second line while the
# original European build fits it on one.
#
# Measured from that overflow: 18 of the 19 glyphs occupied the full 320px, so
# the average advance is ~17.8px at fontX 28.80 with charSpace -2.00.  Scaling
# to 26.00 (~0.90) leaves the string on one line with margin to spare, and the
# 34.20/28.80 aspect ratio is preserved.  Tune here if it reads too small.
#
# German ("Schwarzes Brett", 15 chars) and Italian ("Bacheca", 7) fit at the
# stock size and are deliberately left alone.
FONTS = {
    "dlg_fr.brlyt": {
        "text_up": (26.00, 30.88),
        "next_text_up": (26.00, 30.88),
    },
    # "Tablón de anuncios" is 18 characters -- 18 * 17.8 = 320.4px, a hair over
    # the 320px pane, so it wraps at the stock size exactly like French did.
    # Reusing French's 26.00 lands it at ~289px, and keeps the two long-string
    # locales visually consistent.
    "dlg_es.brlyt": {
        "text_up": (26.00, 30.88),
        "next_text_up": (26.00, 30.88),
    },
}

MIN_BUF = 128
dry_run = "--dry-run" in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith("-")]
blyt_dir = args[0] if args else "usplat/00000004.app/ui/arc/blyt"


def sections(d):
    """Yield (offset, magic, size) for each top-level section."""
    off = 0x10
    while off + 8 <= len(d):
        magic = bytes(d[off:off + 4])
        size = struct.unpack(">I", d[off + 4:off + 8])[0]
        if size < 8 or off + size > len(d):
            break
        yield off, magic, size
        off += size


def set_strings(path, wanted, fonts=None):
    d = open(path, "rb").read()
    out = bytearray(d[:0x10])
    changed = []
    for off, magic, size in sections(d):
        sect = bytearray(d[off:off + size])
        if magic == b"txt1":
            name = bytes(sect[0x0C:0x1C]).split(b"\0")[0].decode("ascii", "replace")
            if fonts and name in fonts:
                struct.pack_into(">ff", sect, 0x64, *fonts[name])
                changed.append((name, "fontSize=%.2fx%.2f" % fonts[name], 0, 0))
            if name in wanted:
                str_off = struct.unpack(">I", sect[0x58:0x5C])[0]
                old_bytes = struct.unpack(">H", sect[0x4E:0x50])[0]
                if str_off and str_off + old_bytes <= len(sect):
                    encoded = wanted[name].encode("utf-16-be") + b"\x00\x00"
                    body = sect[:str_off] + encoded
                    while len(body) % 4:
                        body += b"\x00"
                    sect = bytearray(body)
                    struct.pack_into(">H", sect, 0x4C, max(MIN_BUF, len(encoded)))
                    struct.pack_into(">H", sect, 0x4E, len(encoded))
                    struct.pack_into(">I", sect, 4, len(sect))
                    changed.append((name, wanted[name], old_bytes, len(encoded)))
        out += sect
    struct.pack_into(">I", out, 0x08, len(out))
    if changed and not dry_run:
        open(path, "wb").write(out)
    return changed


if not os.path.isdir(blyt_dir):
    print(f"Error: {blyt_dir} is not a directory.")
    sys.exit(1)

total = 0
for layout, wanted in STRINGS.items():
    path = os.path.join(blyt_dir, layout)
    if not os.path.exists(path):
        print(f"{layout}: missing, skipped")
        continue
    before = os.path.getsize(path)
    for name, text, old, new in set_strings(path, wanted, FONTS.get(layout)):
        if old == 0 and new == 0:
            print(f"{layout:<14} {name:<14} {text}")
        else:
            print(f"{layout:<14} {name:<14} {old:>3} -> {new:>3} bytes  {text!r}")
        total += 1
    after = os.path.getsize(path) if not dry_run else before
    print(f"{layout:<14} file {before} -> {after} bytes")

print(f"\n{total} panes rewritten{' (dry run)' if dry_run else ''}.")
