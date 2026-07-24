#!/usr/bin/env python3
"""Build a My Pokémon Ranch celebrity-guest distribution file (``talent_pt.dat``).

The game downloads this file over WiiConnect24 from
``http://<host>/<3 game chars>/talent_pt.<lang>_<CC>.enc`` and, after AES/RSA
decryption, validates and stores the plaintext described below. The plaintext is
a fixed ``0x19BC`` (6588) byte blob; anything shorter is rejected outright.

Layout was reverse-engineered from ``00000001.app`` (USA, RDKE01). The three
functions worth knowing if you need to extend this:

* ``0x803E317C`` — validates the 24-byte header (version / region / language).
* ``0x803E29AC`` — validates the guest record at ``+0x18`` and text pool at ``+0x9BC``.
* ``0x80356EC0`` — boot-time loader: region/language/period/replay gate, then
  copies ``file+0x18`` (0x9A4 B) to ``save+0x88C`` and ``file+0x9BC`` (0x1000 B)
  to ``save+0x1230``.

File map (all multi-byte fields big-endian)::

    off     size    field
    0x0000  1       version                 must be 0x04
    0x0001  1       region_filter           0xFF = any, else must match console
    0x0002  1       language_filter         0xFF = any, else must match console
    0x0003  1       (pad, 0)
    0x0004  2       0xFFFF (reserved)
    0x0006  2       0x0000 (reserved)
    0x0008  16      0x00 * 16 (reserved)
    0x0018  2       flags                   see GuestFlags
    0x001A  2       wanted_species          National Dex no. the guest wants (<496)
    0x001C  74      mii_1                    RFLCharData (guest #1)
    0x0066  2       mii_1_crc                CRC-16/XMODEM of the 74 Mii bytes
    0x0068  136     pokemon                  Gen-IV 136-byte party/box structure
    0x00F0  4       window_1_open            seconds since 2000-01-01 UTC
    0x00F4  4       window_1_close
    0x00F8  2*4     text_offsets[0:4]        char offsets into the text pools
    0x0100  2048    text_pool_1              UTF-16BE, NUL-separated
    0x0900  4       window_2_open
    0x0904  4       window_2_close
    0x0908  2*2     text_offsets[4:6]
    0x090C  3       date_a                   {year, month, day}, month 1-12 day 1-31
    0x090F  3       date_b                   {year, month, day}
    0x0912  2       object_id_a              gated by flag OBJECT_A (0x200)
    0x0914  2       object_id_b              gated by flag OBJECT_B (0x400)
    0x0916  2       (unchecked)
    0x0918  8       0x00 * 8 (reserved)
    0x0920  2*2     text_offsets[6:8]
    0x0924  74      mii_2                    guest #2, present iff flag GUEST_2 (0x2)
    0x096E  2       mii_2_crc
    0x0970  74      mii_3                    guest #3, present iff flag GUEST_3 (0x4)
    0x09BA  2       mii_3_crc
    0x09BC  4096    text_pool_2              UTF-16BE; final u16 MUST be 0
    0x19BC  --      EOF

The eight ``text_offsets`` are *character* offsets into the text pools: pool #1
holds 1024 chars, pool #2 holds 2048 chars, for 3072 total. The game rejects any
offset >= 0xC00 (3072).

Special "X_" models (balloon Pikachu / Octillery)
-------------------------------------------------
The ranch has two hardcoded override models in ``4:/pii.arc/`` — ``X_PIKATYUU``
(a Pikachu holding balloons) and ``X_OKUTAN`` (Octillery, Golko's trade). Both
are chosen by the model builder at ``0x800CF0F0`` and are driven **entirely by
the celebrity's Pokémon** (the 136-byte PKM at file offset 0x68), not by any
separate flag in this file — so guest data *can* produce them by crafting that
PKM appropriately.

The decoder ``0x803B7AB0`` decrypts the PKM and, from its own contents, sets two
metadata bits that the model builder later reads via ``0x803B66C4``:

* ``X_OKUTAN``  — the PKM decrypts to Octillery (species/form family check).
* ``X_PIKATYUU`` — all of: species == 25 (Pikachu); it knows move 19 (0x13,
  "Fly") in its Attacks block; a specific Misc-block byte equals 0x10; and it
  passes the species/form family + validity checks. In other words: **a
  Fly-knowing Pikachu**, rendered floating with balloons.

Gender (``_F`` / ``_M``) is chosen from the PKM's gender via ``0x803B24F4``.
None of this is a field you set here; it is an emergent property of the
``<pokemon>`` blob. Populate ``<pokemon>`` with a qualifying Pikachu to use it.
"""

import argparse
import binascii
import calendar
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from enum import IntFlag

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

FORMAT_VERSION = 0x04
TOTAL_SIZE = 0x19BC          # the game rejects anything smaller
NANDBOOT_EPOCH = 946684800   # 2000-01-01 00:00:00 UTC, in Unix seconds

MII_SIZE = 74                # RFLCharData
POKEMON_SIZE = 136           # Gen-IV party/box structure
TEXT_POOL_1_SIZE = 2048      # 1024 UTF-16 chars
TEXT_POOL_2_SIZE = 4096      # 2048 UTF-16 chars
MAX_TEXT_OFFSET = 0xC00      # combined char capacity of both pools
MAX_SPECIES = 496            # National Dex bound enforced by the game

ANY_REGION = 0xFF
ANY_LANGUAGE = 0xFF

# One WC24 distribution window is ~14 days. The reference data is generated as a
# rolling series of these windows relative to "now".
WINDOW_SECONDS = 1209599


class GuestFlags(IntFlag):
    """Record flag bits at file offset 0x18 (validated in 0x803E29AC)."""

    TRADE = 0x0001       # enables text offset at 0x920 (celebrity offers a trade)
    GUEST_2 = 0x0002     # a second guest Mii is present at 0x924
    GUEST_3 = 0x0004     # a third guest Mii is present at 0x970 (requires GUEST_2)
    FORCED_EXIT = 0x0020  # kill switch: the whole payload is ignored if set
    OBJECT_A = 0x0200    # enables object_id_a at 0x912
    OBJECT_B = 0x0400    # enables object_id_b at 0x914

    # bits 0x0008 / 0x0010 / 0x0080 / 0x0100 are not validated (free/semantic);
    # bits 0x0040 and 0xF800 must be zero.


def log(msg, level="INFO"):
    print(f"[{level}] {msg}")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def crc16_xmodem(data, crc=0):
    """CRC-16/XMODEM (poly 0x1021) as used for each Mii block's trailing sum."""
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
            crc &= 0xFFFF
    return crc


class StructWriter:
    """Append-only big-endian writer that verifies fields land at known offsets.

    Every ``at(offset)`` call asserts the buffer is exactly that long, so a
    layout mistake fails loudly at build time instead of shipping a malformed
    file that the Wii silently rejects.
    """

    def __init__(self):
        self.buf = bytearray()

    def at(self, offset, label=""):
        if len(self.buf) != offset:
            raise AssertionError(
                f"cursor at 0x{len(self.buf):04X}, expected 0x{offset:04X}"
                + (f" before {label}" if label else "")
            )
        return self

    def u8(self, value):
        if not 0 <= value <= 0xFF:
            raise ValueError(f"u8 out of range: {value}")
        self.buf += struct.pack(">B", value)
        return self

    def u16(self, value):
        if not 0 <= value <= 0xFFFF:
            raise ValueError(f"u16 out of range: {value}")
        self.buf += struct.pack(">H", value)
        return self

    def u32(self, value):
        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(f"u32 out of range: {value}")
        self.buf += struct.pack(">I", value)
        return self

    def raw(self, data):
        self.buf += bytes(data)
        return self

    def zeros(self, count):
        self.buf += b"\x00" * count
        return self


def mii_block(writer, hex_string):
    """Write a 74-byte Mii followed by its CRC-16/XMODEM."""
    data = binascii.unhexlify(hex_string)
    if len(data) != MII_SIZE:
        raise ValueError(f"Mii must be {MII_SIZE} bytes, got {len(data)}")
    writer.raw(data).u16(crc16_xmodem(data))


# --------------------------------------------------------------------------- #
# XML model
# --------------------------------------------------------------------------- #

class Character:
    def __init__(self, mii_hex, text):
        self.mii_hex = (mii_hex or "").strip() or ("00" * MII_SIZE)
        self.text = text  # {locale: {key: value}}

    @property
    def is_empty(self):
        return not self.mii_hex.strip("0")


class Event:
    def __init__(self, pokemon_hex, characters, wanted_species, object_a, object_b):
        self.pokemon_hex = pokemon_hex
        self.characters = characters       # exactly three (padded)
        self.wanted_species = wanted_species
        self.object_a = object_a
        self.object_b = object_b


def _int_field(node, tag, default=0):
    text = node.findtext(tag)
    return int(text.strip()) if text and text.strip() else default


def parse_character(char_node):
    text = {}
    text_node = char_node.find("text")
    if text_node is not None:
        for loc_node in text_node:
            text[loc_node.tag] = {
                s.attrib.get("key"): (s.text or "")
                for s in loc_node.findall("string")
            }
    return Character(char_node.findtext("mii"), text)


def parse_event(root, event_id):
    events = root.findall("event")
    matches = [e for e in events if e.get("id") == str(event_id)]
    if matches:
        event = matches[0]
    elif 0 <= event_id < len(events):
        event = events[event_id]  # fall back to positional index
    else:
        ids = ", ".join(e.get("id", "?") for e in events)
        raise ValueError(f"No event with id {event_id} (available: {ids})")

    pokemon_hex = (event.findtext("pokemon") or "").strip() or ("00" * POKEMON_SIZE)

    celeb = event.find("celebrity")
    characters = [parse_character(c) for c in
                  (celeb.findall("character") if celeb is not None else [])]
    if len(characters) > 3:
        raise ValueError(f"event has {len(characters)} guests; the format allows at most 3")
    # Pad to exactly three guest slots so Mii #2/#3 always have a source.
    while len(characters) < 3:
        characters.append(Character(None, {}))

    return Event(
        pokemon_hex,
        characters,
        wanted_species=_int_field(event, "wanted_species", 0),
        object_a=_int_field(event, "object_a", 0),
        object_b=_int_field(event, "object_b", 0),
    )


def build_text_pool(strings, size):
    """Concatenate NUL-terminated UTF-16BE strings, return (blob, char_offsets).

    ``char_offsets[i]`` is the starting character index of string ``i``.
    """
    blob = bytearray()
    offsets = []
    for value in strings:
        offsets.append(len(blob) // 2)
        if value:
            blob += (value + "\0").encode("utf-16be")
    if len(blob) > size:
        raise ValueError(f"text pool overflows {size} bytes ({len(blob)} used)")
    blob += b"\x00" * (size - len(blob))
    return bytes(blob), offsets


# --------------------------------------------------------------------------- #
# File assembly
# --------------------------------------------------------------------------- #

def build_talent(
    pokemon_hex,
    characters,
    *,
    flags,
    wanted_species,
    region_filter=ANY_REGION,
    language_filter=ANY_LANGUAGE,
    object_id_a=0,
    object_id_b=0,
    date_a=(0, 0, 0),
    date_b=(0, 0, 0),
    locale="en_US",
    now=None,
):
    if wanted_species >= MAX_SPECIES:
        raise ValueError(f"wanted_species {wanted_species} >= {MAX_SPECIES}")

    now = now if now is not None else datetime.now(timezone.utc)
    opening = int(calendar.timegm(now.timetuple())) - NANDBOOT_EPOCH

    # Text of the primary guest goes in pool #1; its eight offsets are the
    # character positions of the first eight strings.
    primary = characters[0].text.get(locale, {})
    pool_1, char_offsets = build_text_pool(list(primary.values()), TEXT_POOL_1_SIZE)
    text_offsets = (char_offsets + [0] * 8)[:8]
    if any(off >= MAX_TEXT_OFFSET for off in text_offsets):
        raise ValueError("a text offset exceeds the 0xC00 character bound")

    w = StructWriter()

    # -- Header (0x00) ----------------------------------------------------- #
    w.u8(FORMAT_VERSION)
    w.u8(region_filter)
    w.u8(language_filter)
    w.u8(0)
    w.u16(0xFFFF)
    w.u16(0x0000)
    w.zeros(16)

    # -- Guest record (0x18) ----------------------------------------------- #
    w.at(0x18, "flags").u16(int(flags))
    w.at(0x1A, "wanted_species").u16(wanted_species)
    w.at(0x1C, "mii_1")
    mii_block(w, characters[0].mii_hex)
    w.at(0x68, "pokemon").raw(binascii.unhexlify(pokemon_hex))

    w.at(0xF0, "window_1").u32(opening + WINDOW_SECONDS * 10)
    w.u32(opening + WINDOW_SECONDS * 11)
    w.at(0xF8, "text_offsets[0:4]")
    for off in text_offsets[0:4]:
        w.u16(off)

    w.at(0x100, "text_pool_1").raw(pool_1)

    w.at(0x900, "window_2").u32(opening + WINDOW_SECONDS * 8)
    w.u32(opening + WINDOW_SECONDS * 9)
    w.at(0x908, "text_offsets[4:6]")
    for off in text_offsets[4:6]:
        w.u16(off)

    w.at(0x90C, "date_a").raw(bytes(date_a))
    w.at(0x90F, "date_b").raw(bytes(date_b))
    w.at(0x912, "object_id_a").u16(object_id_a)
    w.at(0x914, "object_id_b").u16(object_id_b)
    w.at(0x916, "reserved").u16(0)
    w.at(0x918, "reserved").zeros(8)

    w.at(0x920, "text_offsets[6:8]")
    for off in text_offsets[6:8]:
        w.u16(off)

    w.at(0x924, "mii_2")
    mii_block(w, characters[1].mii_hex)
    w.at(0x970, "mii_3")
    mii_block(w, characters[2].mii_hex)

    # -- Text pool #2 (0x9BC) ---------------------------------------------- #
    # Reserved for the second/third guests' text. Its final u16 must be 0,
    # which the zero fill satisfies.
    w.at(0x9BC, "text_pool_2").zeros(TEXT_POOL_2_SIZE)

    w.at(TOTAL_SIZE, "EOF")
    return bytes(w.buf)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        description="Build a My Pokémon Ranch celebrity-guest distribution file."
    )
    parser.add_argument("event", nargs="?", type=int, default=1,
                        help="event id within guest.xml (matches the id= attribute; default: 1)")
    parser.add_argument("--xml", default="guest.xml",
                        help="path to the guest XML (default: guest.xml)")
    parser.add_argument("--locale", default="en_US",
                        help="locale whose strings populate text pool #1")
    parser.add_argument("--out", default="talent.dat",
                        help="plaintext output path (default: talent.dat)")
    parser.add_argument("--wanted-species", type=int, default=None,
                        help="override the event's wanted_species (National Dex no.)")
    parser.add_argument("--object-a", type=int, default=None,
                        help="override the event's object_a (0 disables the field)")
    parser.add_argument("--object-b", type=int, default=None,
                        help="override the event's object_b (0 disables the field)")
    parser.add_argument("--no-encrypt", action="store_true",
                        help="write only the plaintext, skip wc24encrypt.py")
    args = parser.parse_args()

    root = ET.parse(args.xml).getroot()
    event = parse_event(root, args.event)

    # XML supplies the values; the CLI flags are optional per-run overrides.
    wanted_species = event.wanted_species if args.wanted_species is None else args.wanted_species
    object_a = event.object_a if args.object_a is None else args.object_a
    object_b = event.object_b if args.object_b is None else args.object_b

    # Derive the flags from what the event actually contains.
    flags = GuestFlags.TRADE
    if not event.characters[1].is_empty:
        flags |= GuestFlags.GUEST_2
    if not event.characters[2].is_empty:
        flags |= GuestFlags.GUEST_3
    if object_a:
        flags |= GuestFlags.OBJECT_A
    if object_b:
        flags |= GuestFlags.OBJECT_B

    payload = build_talent(
        event.pokemon_hex,
        event.characters,
        flags=flags,
        wanted_species=wanted_species,
        object_id_a=object_a,
        object_id_b=object_b,
        locale=args.locale,
    )
    assert len(payload) == TOTAL_SIZE

    with open(args.out, "wb") as f:
        f.write(payload)
    log(f"wrote {args.out} ({len(payload)} bytes, flags={flags!r})")

    if args.no_encrypt:
        return

    subprocess.run(
        [
            sys.executable, "wc24encrypt.py",
            "-t", "enc",
            "-in", args.out,
            "-out", "talent_pt.ja_JP.enc",
            "-key", "610B782DAD94000572F66AB3AFB6BDEF",
            "-rsa", "ranch.pem",
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
