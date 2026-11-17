#!/usr/bin/env python3
"""Pack the linked classic_pad ELF into classic_pad.bin for appl.py.

Format (big-endian):
    b"CPAD"  u32 entry  u32 count
    count x { u32 addr  u32 size  size bytes, zero-padded to 4 }
"""
import struct
import sys

SHF_ALLOC = 0x2
SHT_NOBITS = 8


def sections(elf):
    if elf[:4] != b"\x7fELF" or elf[4] != 1 or elf[5] != 2:
        sys.exit("pack.py: expected a 32-bit big-endian ELF")
    entry = struct.unpack_from(">I", elf, 0x18)[0]
    shoff = struct.unpack_from(">I", elf, 0x20)[0]
    shentsize, shnum, shstrndx = struct.unpack_from(">HHH", elf, 0x2E)
    hdrs = [struct.unpack_from(">10I", elf, shoff + i * shentsize) for i in range(shnum)]
    strtab = hdrs[shstrndx]
    names = elf[strtab[4]:strtab[4] + strtab[5]]
    out = []
    for h in hdrs:
        name_off, sh_type, flags, addr, off, size = h[:6]
        name = names[name_off:names.index(b"\0", name_off)].decode()
        if flags & SHF_ALLOC and size:
            if sh_type == SHT_NOBITS:
                sys.exit(f"pack.py: {name} has no file contents (bss?)")
            out.append((name, addr, elf[off:off + size]))
    return entry, out


def main():
    elf_path, bin_path = sys.argv[1:3]
    entry, secs = sections(open(elf_path, "rb").read())
    blob = bytearray(b"CPAD" + struct.pack(">II", entry, len(secs)))
    for name, addr, data in sorted(secs, key=lambda s: s[1]):
        print(f"  {name:8} 0x{addr:08X}-0x{addr + len(data):08X}  {len(data):4} bytes")
        blob += struct.pack(">II", addr, len(data)) + data
        blob += b"\0" * (-len(data) % 4)
    open(bin_path, "wb").write(blob)
    total = sum(len(d) for _, _, d in secs)
    print(f"  entry 0x{entry:08X}, {total} bytes in {len(secs)} pieces")


if __name__ == "__main__":
    main()
