"""
Static analysis helper for the Ranch main DOL (00000001.app).

Parses the DOL section table, converts between file offsets and virtual
addresses, finds cross-references to a string/data address (including the
common "addi rX, rBase, off" form the compiler uses for string pools), lists
callers of a function, and disassembles a range.

Used to map out the pkfmj.nintendo.co.jp save upload/download code; see
pkfmj_netcode.md for the results.

Usage:
    python3 dolnet.py sections [dol]
    python3 dolnet.py strings  [dol]            # locate the pkfmj endpoints
    python3 dolnet.py xref   <vaddr> [dol]
    python3 dolnet.py callers <vaddr> [dol]
    python3 dolnet.py dis    <vaddr> [count] [dol]

Disassembly requires capstone (pip install capstone); everything else is
pure stdlib.
"""

import os
import struct
import sys

DEFAULT_DOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "00000001.app")

# Text sections live below this; anything at or above it is data.
DATA_BASE = 0x805CFE00


class Dol:
    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        offs = struct.unpack(">18I", self.data[0:72])
        addrs = struct.unpack(">18I", self.data[72:144])
        sizes = struct.unpack(">18I", self.data[144:216])
        self.sections = [
            (o, a, s) for o, a, s in zip(offs, addrs, sizes) if s
        ]

    def f2v(self, off):
        for o, a, s in self.sections:
            if o <= off < o + s:
                return a + (off - o)
        return None

    def v2f(self, addr):
        for o, a, s in self.sections:
            if a <= addr < a + s:
                return o + (addr - a)
        return None

    def code_sections(self):
        return [x for x in self.sections if x[1] < DATA_BASE]

    def word(self, off):
        return struct.unpack(">I", self.data[off:off + 4])[0]


def find_strings(dol, needle=b"pkfmj.nintendo.co.jp"):
    """Report every NUL-terminated string containing needle, with its vaddr."""
    out = []
    start = 0
    while True:
        i = dol.data.find(needle, start)
        if i < 0:
            break
        start = i + 1
        beg = dol.data.rfind(b"\x00", 0, i) + 1
        end = dol.data.find(b"\x00", i)
        va = dol.f2v(beg)
        if va is not None:
            out.append((va, dol.data[beg:end].decode("latin1")))
    return out


def xrefs(dol, target):
    """
    Find code references to target.

    Tracks constants built with addis/addi across each section, so it catches
    both the plain lis/addi pair and the base-pointer form the compiler uses
    for string pools (lis+addi once into r29/r30, then addi rX, r30, off for
    each individual string). A naive pair scan misses most of the latter.
    """
    hits = []
    for o, a, size in dol.code_sections():
        regs = {}
        for i in range(0, size, 4):
            w = dol.word(o + i)
            va = a + i
            op = w >> 26
            rt, ra, imm = (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if op == 15:  # addis
                base = 0 if ra == 0 else regs.get(ra)
                if base is None:
                    regs.pop(rt, None)
                else:
                    regs[rt] = (base + (imm << 16)) & 0xFFFFFFFF
            elif op == 14:  # addi
                base = 0 if ra == 0 else regs.get(ra)
                if base is None:
                    regs.pop(rt, None)
                else:
                    v = (base + simm) & 0xFFFFFFFF
                    regs[rt] = v
                    if v == target:
                        hits.append(va)
    return hits


def callers(dol, target):
    """Every b/bl whose destination is target, with the enclosing function."""
    out = []
    for o, a, size in dol.code_sections():
        for i in range(0, size, 4):
            w = dol.word(o + i)
            if (w >> 26) != 18:
                continue
            li = w & 0x03FFFFFC
            if li & 0x02000000:
                li -= 0x04000000
            dst = li if (w & 2) else (a + i + li)
            if dst == target:
                out.append((a + i, "bl" if (w & 1) else "b"))
    return out


def func_start(dol, addr):
    """Walk back to the nearest stwu r1, -x(r1) prologue."""
    f = dol.v2f(addr)
    if f is None:
        return None
    for j in range(f, max(0, f - 0x4000), -4):
        w = dol.word(j)
        if (w >> 26) == 37 and ((w >> 21) & 31) == 1 and ((w >> 16) & 31) == 1:
            return dol.f2v(j)
    return None


def disasm(dol, addr, count):
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_PPC,
                     capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
    f = dol.v2f(addr)
    if f is None:
        raise SystemExit(f"{addr:#x} is not mapped")
    for ins in md.disasm(dol.data[f:f + count * 4], addr):
        print(f"{ins.address:08x}  {ins.mnemonic} {ins.op_str}")


def main():
    args = sys.argv[1:]
    if not args:
        raise SystemExit(__doc__)
    cmd = args.pop(0)
    nums = [a for a in args if not os.path.exists(a)]
    paths = [a for a in args if os.path.exists(a)]
    dol = Dol(paths[0] if paths else DEFAULT_DOL)

    if cmd == "sections":
        for o, a, s in dol.sections:
            kind = "text" if a < DATA_BASE else "data"
            print(f"{kind}  file {o:#010x}  vaddr {a:#010x}  size {s:#x}")
    elif cmd == "strings":
        for va, s in find_strings(dol):
            print(f"{va:08x}  {s}")
    elif cmd == "xref":
        target = int(nums[0], 16)
        for va in xrefs(dol, target):
            fs = func_start(dol, va)
            print(f"{va:08x}  in func {fs:08x}" if fs else f"{va:08x}")
    elif cmd == "callers":
        target = int(nums[0], 16)
        for va, kind in callers(dol, target):
            fs = func_start(dol, va)
            print(f"{va:08x} {kind}  in func {fs:08x}" if fs else f"{va:08x} {kind}")
    elif cmd == "dis":
        addr = int(nums[0], 16)
        count = int(nums[1], 0) if len(nums) > 1 else 64
        disasm(dol, addr, count)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
