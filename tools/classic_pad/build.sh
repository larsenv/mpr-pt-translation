#!/usr/bin/env bash
# Rebuilds classic_pad.bin from classic_pad.c with devkitPPC.
#
# The server build (61.sh) does NOT run this -- it has no devkitPPC.  appl.py
# reads the committed classic_pad.bin, so rerun this and commit the .bin
# whenever classic_pad.c or classic_pad.ld changes.
set -euo pipefail
cd "$(dirname "$0")"

DEVKITPPC="${DEVKITPPC:-/opt/devkitpro/devkitPPC}"
CC="$DEVKITPPC/bin/powerpc-eabi-gcc"

# -Os: the gaps are small.  -G0 -msdata=none: r2/r13 belong to the game.
"$CC" -mcpu=750 -meabi -mhard-float -Os -G0 -msdata=none \
    -ffreestanding -fno-builtin -nostdlib -fno-zero-initialized-in-bss \
    -fno-tree-loop-distribute-patterns -fno-asynchronous-unwind-tables \
    -fno-unwind-tables -fno-common -Wall -Wextra -Werror \
    -T classic_pad.ld -Wl,--no-undefined -Wl,--gc-sections \
    -o classic_pad.elf classic_pad.c -lgcc

python3 pack.py classic_pad.elf classic_pad.bin
rm -f classic_pad.elf
