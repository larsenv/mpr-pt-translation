#!/usr/bin/env python3
"""Set the IOS a title requires, in its TMD.

My Pokemon Ranch ships requiring IOS35, which has no SDHC (SDv2) support.
The SDHC patch baked into 00000001.app only fixes the SD driver's byte->block
addressing; it does NOT initialise the card -- that is IOS's job.  Under IOS35
nothing ever initialises an SDHC card, so the driver gives up and the game says
"the card inserted in the SD card slot is not recognized" no matter how correct
the addressing patch is.  Repointing the title at an SDHC-capable IOS is what
actually makes SDHC work.

Usage:
    python3 patch_tmd_ios.py <title.tmd> [ios_version]      # default 58
    python3 patch_tmd_ios.py <title.tmd> --show             # read-only
    python3 patch_tmd_ios.py <title.tmd> 58 --no-backup     # for build pipelines

A .bak is made on first run and restored from on subsequent runs, so repeated
invocations are idempotent (same convention as appl.py).

NOTE: this invalidates the TMD signature.  Dolphin does not check it for NAND
titles, so the raw edit is enough there.  For real hardware the WAD must be
fakesigned (trucha) after patching, and the target IOS must be installed.
"""
import os
import shutil
import struct
import sys

# IOS versions Dolphin grants Feature::SDv2 (Source/Core/Core/IOS/VersionInfo.cpp,
# GetFeatures).  This mirrors real hardware: these are the IOS revisions with
# SDHC support in their SDI module.
SDHC_CAPABLE = set([48, 70, 80]) | set(range(56, 63))

# signature type -> bytes to skip to reach the TMD header (type + sig + padding)
SIG_HEADER_SIZE = {
    0x00010000: 4 + 512 + 60,  # RSA-4096
    0x00010001: 4 + 256 + 60,  # RSA-2048
    0x00010002: 4 + 60 + 64,   # ECDSA
}


def header_offset(data):
    sig_type = struct.unpack_from(">I", data, 0)[0]
    if sig_type not in SIG_HEADER_SIZE:
        raise SystemExit("Unrecognised TMD signature type %#010x" % sig_type)
    return SIG_HEADER_SIZE[sig_type]


def describe(data):
    off = header_offset(data)
    issuer = data[off:off + 64].rstrip(b"\0").decode("ascii", "replace")
    ios_tid = struct.unpack_from(">Q", data, off + 0x44)[0]
    title_id = struct.unpack_from(">Q", data, off + 0x4C)[0]
    return off, issuer, ios_tid, title_id


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)

    path = argv[1]
    rest = argv[2:]
    show_only = "--show" in rest
    no_backup = "--no-backup" in rest
    positional = [x for x in rest if not x.startswith("--")]
    ios = int(positional[0], 0) if positional else 58

    if not os.path.exists(path):
        raise SystemExit("Error: could not find %s." % path)

    backup = path + ".bak"
    if not show_only and not no_backup:
        # Same clean-slate convention as appl.py.
        if os.path.exists(backup):
            shutil.copyfile(backup, path)
            print("Restored from %s" % backup)
        else:
            shutil.copyfile(path, backup)
            print("Created backup at %s" % backup)

    data = bytearray(open(path, "rb").read())
    off, issuer, ios_tid, title_id = describe(data)
    cur_ios = ios_tid & 0xFFFFFFFF

    print("TMD:          %s" % path)
    print("  issuer:     %s" % issuer)
    print("  title id:   %016x" % title_id)
    print("  requires:   %016x (IOS%d)%s"
          % (ios_tid, cur_ios, "" if cur_ios in SDHC_CAPABLE else "  <- no SDHC support"))

    if show_only:
        return 0

    if ios not in SDHC_CAPABLE:
        print("  WARNING: IOS%d is not in the SDHC-capable set %s; SDHC will not work."
              % (ios, sorted(SDHC_CAPABLE)))

    new_tid = 0x0000000100000000 | ios
    if new_tid == ios_tid:
        print("Already requires IOS%d; nothing to do." % ios)
        return 0

    struct.pack_into(">Q", data, off + 0x44, new_tid)
    open(path, "wb").write(data)
    print("Patched:      %016x (IOS%d) -> %016x (IOS%d)"
          % (ios_tid, cur_ios, new_tid, ios))
    print("Signature is now invalid -- fakesign the WAD for real hardware.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
