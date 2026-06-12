import guestz
import xml.etree.ElementTree as ET
from xml.dom import minidom
import binascii
import re

def remove_invalid_xml_chars(val):
    if not isinstance(val, str):
        return val
    # Remove control characters except for \t (0x09), \n (0x0A), \r (0x0D)
    # \x00 is specifically not allowed in XML
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', val)

root = ET.Element("characters")

locales = ["en_US", "ja_JP", "de_DE", "fr_FR", "es_ES", "it_IT"]

for i in range(len(guestz.mii)):
    mii_hex = guestz.mii[i]
    pokemon_hex = guestz.pokemon[i] if i < len(guestz.pokemon) else ""
    text_data = guestz.text[i] if i < len(guestz.text) else {}
    
    # decode name
    if mii_hex:
        mii_bytes = binascii.unhexlify(mii_hex)
        name_bytes = mii_bytes[2:18]
        name = name_bytes.decode('utf-16be').rstrip('\x00')
    else:
        name = "Unknown"
        
    char_node = ET.SubElement(root, "character", name=name)
    
    mii_node = ET.SubElement(char_node, "mii")
    mii_node.text = mii_hex
    
    poke_node = ET.SubElement(char_node, "pokemon")
    poke_node.text = pokemon_hex
    
    text_node = ET.SubElement(char_node, "text")
    
    # Figure out number of strings from existing locales
    num_strings = 0
    for loc, strings in text_data.items():
        if len(strings) > num_strings:
            num_strings = len(strings)
            
    if num_strings == 0:
        num_strings = 9 # default
        
    for loc in locales:
        loc_node = ET.SubElement(text_node, loc)
        
        strings = text_data.get(loc, [])
        for j in range(num_strings):
            str_node = ET.SubElement(loc_node, "string", index=str(j))
            if j < len(strings) and strings[j]:
                # replace literal null byte or newlines if we want, or just put them as is
                str_node.text = remove_invalid_xml_chars(strings[j])
            else:
                str_node.text = ""

xmlstr = minidom.parseString(ET.tostring(root, 'utf-8')).toprettyxml(indent="  ")
with open("guestz.xml", "w", encoding="utf-8") as f:
    f.write(xmlstr)
