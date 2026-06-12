import subprocess
import struct
import binascii
import calendar
from datetime import datetime, timezone


def log(msg, level="INFO"):
    print(f"[{level}] {msg}")


def u8(data):
    if not 0 <= data <= 255:
        log(f"u8 out of range: {data}", "INFO")
        data = 0
    return struct.pack(">B", data)


def u16(data):
    if not 0 <= data <= 65535:
        log(f"u16 out of range: {data}", "INFO")
        data = 0
    return struct.pack(">H", data)


def u32(data):
    if not 0 <= data <= 4294967295:
        log(f"u32 out of range: {data}", "INFO")
        data = 0
    return struct.pack(">I", data)


def crc16_xmodem(data, crc=0):
    poly = 0x1021
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            crc = (crc << 1) ^ poly if (crc & 0x8000) else crc << 1
            crc &= 0xFFFF
    return crc


opening_timestamp = int(calendar.timegm(datetime.now(timezone.utc).timetuple())) - 946684800

import sys
import xml.etree.ElementTree as ET

tree = ET.parse("guest.xml")
root = tree.getroot()

event_idx = int(sys.argv[1]) if len(sys.argv) > 1 else 0
events = root.findall("event")
if event_idx >= len(events):
    raise ValueError(f"Event index {event_idx} out of range")

event_node = events[event_idx]

pokemon = []
mii = []
text = []

chars = list(event_node.findall("character"))

# Pad up to 3 guests
for i in range(3):
    if i < len(chars):
        char_node = chars[i]
        mii.append(char_node.find("mii").text or "")
        pokemon.append(char_node.find("pokemon").text or "")
        
        char_text = {}
        text_node = char_node.find("text")
        if text_node is not None:
            for loc_node in text_node:
                loc = loc_node.tag
                char_text[loc] = {}
                for str_node in loc_node.findall("string"):
                    key = str_node.attrib.get("key")
                    val = str_node.text or ""
                    char_text[loc][key] = val
        text.append(char_text)
    else:
        # Empty guest
        mii.append("00" * 74)
        pokemon.append("00" * 136)
        text.append({})

# Append the \0 terminator only to populated strings
en_US_text_list = [val + "\0" if val else "" for val in text[0].get("en_US", {}).values()]


def get_utf16_len(count):
    return len("".join(en_US_text_list[:count]).encode("utf-16be")) // 2


celebrity = {
    "unknown1": binascii.unhexlify("04ffff00ffff00"),
    "unknown2": binascii.unhexlify("00000000000000000000000000000000000789"),
    
    "wanted_pokemon_0": u16(66),
    "celebrity_mii_0": binascii.unhexlify(mii[0]),
    "celebrity_mii_xmodem_0": u16(crc16_xmodem(binascii.unhexlify(mii[0]))),
    "celebrity_pokemon_0": binascii.unhexlify(pokemon[0]),

    "wanted_pokemon_1": u16(66 if mii[1] != "00"*74 else 0),
    "celebrity_mii_1": binascii.unhexlify(mii[1]),
    "celebrity_mii_xmodem_1": u16(crc16_xmodem(binascii.unhexlify(mii[1]))),
    "celebrity_pokemon_1": binascii.unhexlify(pokemon[1]),

    "wanted_pokemon_2": u16(66 if mii[2] != "00"*74 else 0),
    "celebrity_mii_2": binascii.unhexlify(mii[2]),
    "celebrity_mii_xmodem_2": u16(crc16_xmodem(binascii.unhexlify(mii[2]))),
    "celebrity_pokemon_2": binascii.unhexlify(pokemon[2]),

    "opening_timestamp_1": u32(opening_timestamp + (1209599 * 10)),
    "closing_timestamp_1": u32(opening_timestamp + (1209599 * 11)),
    "unknown_3": u16(0),
    "text_size_section_1": u16(get_utf16_len(1)),
    "text_size_section_2": u16(get_utf16_len(2)),
    "text_size_section_3": u16(get_utf16_len(3)),
}

for i, section in enumerate(en_US_text_list, start=1):
    celebrity[f"celebrity_dialog_{i}"] = section.encode("utf-16be")

celebrity.update({
    "celebrity_dialog_padding": u8(0) * (2048 - get_utf16_len(len(en_US_text_list)) * 2),
    "opening_timestamp_2": u32(opening_timestamp + (1209599 * 8)),
    "closing_timestamp_2": u32(opening_timestamp + (1209599 * 9)),
    "text_size_section_4": u16(get_utf16_len(4)),
    "text_size_section_5": u16(get_utf16_len(5)),
    "unknown_4": u32(0),
    "unknown_5": u32(3060),
    "unknown_6": u32(62),
    "unknown_7": u32(0),
    "unknown_8": u32(0),
    "text_size_section_6": u16(get_utf16_len(6)),
    "text_size_section_7": u16(get_utf16_len(7)),
    "unknown_9": u8(0) * 4248
})

with open("talent.dat", "wb") as f:
    for value in celebrity.values():
        f.write(value)

subprocess.run([
    "/usr/bin/python3", "wc24encrypt.py", 
    "-t", "enc", 
    "-in", "talent.dat", 
    "-out", "/opt/nwcs/wbm/talent_pt.ja_JP.enc", 
    "-key", "610B782DAD94000572F66AB3AFB6BDEF", 
    "-rsa", "/opt/key/ranch.pem"
], check=True)
