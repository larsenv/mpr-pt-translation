#!/usr/bin/env python3
"""Clone dlg_b4_*.brlan into dlg_de/es/fr/it_*.brlan inside ui.arc.

ui.arc already carries dlg_de/dlg_es/dlg_fr/dlg_it BRLYTs -- wider clones of
dlg_b4 for the languages whose button text overflows -- but it carries no
matching BRLANs.  The layout loader (sub_80154674) stores "<layout>_" as the
animation prefix and sub_80155540 resolves every animation as
"<prefix><name>.brlan"; when that lookup fails it returns NULL, which is what
crashes the four-button dialog once appl.py points those layouts at a European
locale.

The BRLANs only reference pane names, and dlg_XX.brlyt has exactly the same
pane set as dlg_b4.brlyt, so byte-identical copies under new names are enough.

Usage: python3 tools/dlg_locale_anims.py usplat/00000004.app/ui/arc/anim
"""

import os
import shutil
import sys

LANGS = ("de", "es", "fr", "it")
SRC_PREFIX = "dlg_b4_"

anim_dir = sys.argv[1] if len(sys.argv) > 1 else "usplat/00000004.app/ui/arc/anim"

if not os.path.isdir(anim_dir):
    print(f"Error: {anim_dir} is not a directory.")
    sys.exit(1)

sources = sorted(
    f for f in os.listdir(anim_dir)
    if f.startswith(SRC_PREFIX) and f.endswith(".brlan")
)
if not sources:
    print(f"Error: no {SRC_PREFIX}*.brlan found in {anim_dir}.")
    sys.exit(1)

created = 0
for lang in LANGS:
    layout = os.path.join(os.path.dirname(anim_dir.rstrip("/")), "blyt", f"dlg_{lang}.brlyt")
    if not os.path.exists(layout):
        print(f"Skipping {lang}: {layout} is missing.")
        continue
    for src in sources:
        dst = f"dlg_{lang}_" + src[len(SRC_PREFIX):]
        shutil.copyfile(os.path.join(anim_dir, src), os.path.join(anim_dir, dst))
        created += 1

print(f"Created {created} animation files in {anim_dir} ({len(sources)} per language).")
