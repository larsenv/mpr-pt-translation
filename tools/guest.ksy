meta:
  id: mpr_talent_pt
  title: My Pokemon Ranch celebrity-guest distribution (decrypted talent_pt.dat)
  file-extension: dat
  endian: be
  license: CC0-1.0
doc: |
  Decrypted plaintext of `talent_pt.<lang>_<CC>.enc`, downloaded over WiiConnect24
  by My Pokemon Ranch (RDKE01) from
  `http://<host>/<3 game chars>/talent_pt.<lang>_<CC>.enc`. Fixed size 0x19BC
  (6588) bytes; the game rejects anything shorter.

  Reverse-engineered from 00000001.app (USA): header validator 0x803E317C,
  record validator 0x803E29AC, boot loader 0x80356EC0 (which copies the record
  at +0x18 to save+0x88C and text pool #2 at +0x9BC to save+0x1230).
doc-ref: https://github.com/larsenv/mpr-pt-translation
seq:
  - id: header
    type: header
  - id: record
    type: guest_record
  - id: text_pool_2
    size: 0x1000
    doc: |
      UTF-16BE text for the 2nd/3rd guests (file 0x9BC). Copied to save+0x1230.
      The final u16 (file 0x19BA) MUST be 0 or the record is rejected.
types:
  header:
    doc: File 0x00..0x17. All reserved fields must hold the values shown.
    seq:
      - id: version
        type: u1
        valid: 0x04
        doc: Format version; must be 4.
      - id: region_filter
        type: u1
        doc: 0xFF = any region; else must equal the console region (0x0C is also wildcarded).
      - id: language_filter
        type: u1
        doc: 0xFF = any language; else must equal the console language.
      - id: reserved_03
        contents: [0x00]
      - id: reserved_04
        type: u2
        doc: Must be 0xFFFF.
      - id: reserved_06
        type: u2
        doc: Must be 0.
      - id: reserved_08
        size: 16
        doc: Must be all zero.
  guest_record:
    doc: |
      0x9A4 bytes (file 0x18..0x9BB), copied verbatim to save+0x88C on import.
      Offsets in the field docs are absolute file offsets.
    seq:
      - id: flags
        type: u2
        doc: Guest flags; see the has_* / forced_exit instances. File 0x18.
      - id: wanted_species
        type: u2
        doc: National Dex no. the guest asks you to bring (< 496; 0 = no trade). File 0x1A.
      - id: mii_1
        type: mii_block
        doc: Guest #1 (always present). File 0x1C.
      - id: pokemon
        size: 136
        doc: |
          The guest's Pokemon as a Gen-IV PK4 (136-byte box format, encrypted).
          File 0x68. On import the ranch wraps it into an RK4 = PK4 + a 28-byte
          unencrypted extension (OwnershipType 0x88, OwnershipStatus 0x8A big-endian,
          Handling Trainer TID/SID 0x8C, HT name 0x90..0xA3). That extension is NOT
          stored in this file; the bytes after the PK4 are the distribution window
          below. See PKHeX RK4.cs.
      - id: window_1_open
        type: u4
        doc: Distribution window open, seconds since 2000-01-01 UTC. File 0xF0.
      - id: window_1_close
        type: u4
        doc: Distribution window close. File 0xF4.
      - id: text_offsets_a
        type: u2
        repeat: expr
        repeat-expr: 4
        doc: Char offsets (slots 0-3) into the text pools; each must be < 0xC00. File 0xF8.
      - id: text_pool_1
        size: 2048
        doc: UTF-16BE text for guest #1, NUL-separated (1024 chars). File 0x100.
      - id: window_2_open
        type: u4
        doc: Second window pair, open. File 0x900.
      - id: window_2_close
        type: u4
        doc: Second window pair, close. File 0x904.
      - id: text_offsets_b
        type: u2
        repeat: expr
        repeat-expr: 2
        doc: Char offsets (slots 4-5). File 0x908.
      - id: date_a
        type: ymd
        doc: File 0x90C.
      - id: date_b
        type: ymd
        doc: File 0x90F.
      - id: object_id_a
        type: u2
        doc: |
          Species/form-family ID, validated (0x803A8498) only when flag 0x200 is set.
          File 0x912.
      - id: object_id_b
        type: u2
        doc: Species/form-family ID, validated only when flag 0x400 is set. File 0x914.
      - id: reserved_916
        type: u2
        doc: Not validated. File 0x916.
      - id: reserved_918
        size: 8
        doc: Must be all zero. File 0x918.
      - id: text_offsets_c
        type: u2
        repeat: expr
        repeat-expr: 2
        doc: |
          Char offsets (slots 6-7). Slot 6 (0x920) must be 0 unless flag 0x1 (trade)
          is set. File 0x920.
      - id: mii_2
        type: mii_block
        doc: Guest #2, valid iff flag 0x2 is set. File 0x924.
      - id: mii_3
        type: mii_block
        doc: Guest #3, valid iff flag 0x4 is set (which requires 0x2). File 0x970.
    instances:
      has_trade:
        value: (flags & 0x0001) != 0
        doc: Celebrity offers a Pokemon trade (optional). Enables text offset slot 6.
      has_guest_2:
        value: (flags & 0x0002) != 0
      has_guest_3:
        value: (flags & 0x0004) != 0
      forced_exit:
        value: (flags & 0x0020) != 0
        doc: Kill switch; the whole payload is ignored if set.
      has_object_a:
        value: (flags & 0x0200) != 0
      has_object_b:
        value: (flags & 0x0400) != 0
  mii_block:
    doc: 74-byte Wii Mii (RFLCharData) followed by its CRC-16/XMODEM.
    seq:
      - id: data
        size: 74
      - id: crc16_xmodem
        type: u2
  ymd:
    doc: 3-byte date; month (1-12) and day (1-31) are validated when the field is non-zero.
    seq:
      - id: year
        type: u1
      - id: month
        type: u1
      - id: day
        type: u1
