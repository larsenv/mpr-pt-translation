import sys
import shutil
import struct
import os

filepath = sys.argv[2]
region = sys.argv[1]
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
    d = f.read()
    d = d.replace(b"nwcs.wapp.wii.com", b"nwcs.wii.rc24.xyz")
    h1 = "C9F53486A813945FE4C5595A5347F3DC4FDA3D49E121FADEDF6EB814FDFEB8E1861DC42E44F1337A3159F30C2597098DAC5DF174086765C7455319555A7DB30325EE79DB7BDDFDD2BCA236C15E1273FF31FD7F864CF2DAA27F9BFC44DAFE4194E51FE505E95D570E2467020540A7221E66DAE6AEEAB54B87781A4152D25EAA5717C03C8E057E4C992626487AB6598178A659E7C0372668B2DBAFB6B3CC4BBDD1485E6D9CE1FFB474D7E408E63892B9B646B61D98A1838ED8085234BE8CF57E804A5BAD364AEFA6FB826E6DDA98A9131F72CCE234935D2F89069B0903B9711C0D53B5BC515BFFA8C91CBE81E6E13E0257EE0309BEB83B584A5EBA86A815815389"
    h2 = "B54D45F92D48A51AB63EF9713F8CBACE59BF80DDD61FB3314A3124F158E6E07C01A160E91F223B1AB254433F343A717D766901CA706763D81C51DC4B53159A7F85D4DA6A650DFC46E4A95EDBFD3D6FBF0A46C6865A65FF684076A797E969DBA67DC1BBBE5C3500FAF7A15FEA80C5B987C6F022FC772362B9A6D927D72211C986F32351EDD46E9F1F0356B1278A8262D54C0FDDE68DF4BE3D31B480530B85045F06BF2904B2B42021FAE34702B2AE1EA9BF15EFBF3E0137A02FDDE1FE5B18DF235A1C5D9814A9ABC55E55CAF56654A153ED385AD1C2A3F63D63DF88F3336280383BE24EAEDF98D17CDC0C12435F9B8A9C3DA394A92F4D24EEF1851A88DBC85AD5"
    d = d.replace(bytes.fromhex(h1), bytes.fromhex(h2))
    f.seek(0)
    f.write(d)
    
    f.seek(0x2c42fc)
    f.write(bytes.fromhex("7FE6FB787FA7EB787F68DB78"))
    print("Code 1 applied.")

    if region == "EUR":
        # 2. Inject Payload into 128 bytes of free space in Text 0
        payload_addr = 0x800044F0
        payload_offset = 0x5F0
    
        hook_addr = 0x8036EBC4
        hook_offset = 0x2B2184
    
        # The hook sits on `mr r6, r3` at 0x8036EBC4, right after the call that
        # returns the locale string ("en_GB", "de_DE", ...).  Two globals hold
        # the BRLYT name of the four-button dialog and both default to "dlg_b4":
        #
        #   0x807BF308 (r13-0x3798)  used by sub_80336280
        #   0x807BFD88 (r13-0x2D18)  used by sub_803D7EA8
        #
        # For the EUR build, 61.sh renames dlg_b4 -> dlg_en and then derives
        # dlg_es / dlg_de / dlg_it / dlg_fr from it, animations included, so the
        # names that exist in the built ui.arc are exactly en/de/es/fr/it.
        # dlg_b4 is GONE from that archive -- never fall back to it here.
        #
        # The layout name doubles as the animation prefix (sub_80154674 stores
        # "<layout>_" and sub_80155540 resolves "<prefix><anim>.brlan",
        # returning NULL on a miss), so a name without matching BRLANs crashes
        # the dialog.  Locales 61.sh does not generate -- nl_NL, and anything
        # else the table in sub_80337A78 can return -- fall back to dlg_en.
        payload_hex = (
            "A0030000"    # lhz    r0, 0(r3)          ; first two chars of locale
            "28006465"    # cmplwi r0, 0x6465         ; "de"
            "41820028"    # beq    apply
            "28006672"    # cmplwi r0, 0x6672         ; "fr"
            "41820020"    # beq    apply
            "28006573"    # cmplwi r0, 0x6573         ; "es"
            "41820018"    # beq    apply
            "28006974"    # cmplwi r0, 0x6974         ; "it"
            "41820010"    # beq    apply
            "2800656E"    # cmplwi r0, 0x656E         ; "en"
            "41820008"    # beq    apply
            "3800656E"    # li     r0, 0x656E         ; unhandled locale -> "en"
            "3D60807C"    # apply: lis r11, 0x807C
            "3D20646C"    # lis    r9, 0x646C         ; "dl"
            "6129675F"    # ori    r9, r9, 0x675F     ; "dlg_"
            "39000000"    # li     r8, 0
            "394BF308"    # addi   r10, r11, -0xCF8   ; 0x807BF308
            "912A0000"    # stw    r9, 0(r10)
            "B00A0004"    # sth    r0, 4(r10)
            "990A0006"    # stb    r8, 6(r10)
            "394BFD88"    # addi   r10, r11, -0x278   ; 0x807BFD88
            "912A0000"    # stw    r9, 0(r10)
            "B00A0004"    # sth    r0, 4(r10)
            "990A0006"    # stb    r8, 6(r10)
            "7C661B78"    # mr     r6, r3             ; displaced instruction
        )
        payload_bytes = bytearray.fromhex(payload_hex)
        branch_back_addr = payload_addr + len(payload_bytes)
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
