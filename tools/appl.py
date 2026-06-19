import sys
import shutil
import struct
import os

filepath = sys.argv[1]
backup_filepath = filepath + ".bak"

if not os.path.exists(filepath):
    print(f"Error: Could not find {filepath}.")
    exit(1)

# Ensure clean slate from backup
if os.path.exists(backup_filepath):
    shutil.copyfile(backup_filepath, filepath)
    print(f"Restored from {backup_filepath}")
else:
    shutil.copyfile(filepath, backup_filepath)
    print(f"Created backup at {backup_filepath}")

def make_branch(src, dst):
    offset = dst - src
    if offset < 0:
        offset += (1 << 26)
    return 0x48000000 | (offset & 0x03FFFFFC)

with open(filepath, "r+b") as f:
    # 1. Apply Code 1
    f.seek(0x2c42fc)
    f.write(bytes.fromhex("7FE6FB787FA7EB787F68DB78"))
    print("Code 1 applied.")

    # 2. Inject Payload into 128 bytes of free space in Text 0
    payload_addr = 0x800044F0
    payload_offset = 0x5F0

    hook_addr = 0x8036EBC4
    hook_offset = 0x2B2184

    payload_hex = (
        "9421FFE090610008"
        "9361000C48000011"
        "646C675F252E3273"
        "000000007F6802A6"
        "3C60807C3863F308"
        "388000087F65DB78"
        "80C100083D80800C"
        "398C1BD87D8903A6"
        "4E8004213C60807C"
        "3863FD8838800008"
        "7F65DB7880C10008"
        "3D80800C398C1BD8"
        "7D8903A64E800421"
        "8361000C80610008"
        "7C661B7838210020"
    )
    payload_bytes = bytearray.fromhex(payload_hex)
    branch_back_addr = payload_addr + 120
    branch_back_inst = make_branch(branch_back_addr, hook_addr + 4)
    payload_bytes.extend(struct.pack(">I", branch_back_inst))
    payload_bytes.extend(bytes.fromhex("00000000"))

    f.seek(payload_offset)
    f.write(payload_bytes)
    print(f"Injected payload to free space in Text 0 at offset {hex(payload_offset)}")

    # 3. Write Branch at Hook
    f.seek(hook_offset)
    f.write(struct.pack(">I", make_branch(hook_addr, payload_addr)))
    print("Hook injected.")

print("Successfully applied Gecko codes to 00000001.app!")
