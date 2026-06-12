import xml.etree.ElementTree as ET
from xml.dom import minidom
import binascii
import re
import ast

def remove_invalid_xml_chars(val):
    if not isinstance(val, str):
        return val
    return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', val)

namespace = {}
with open("guest.py", "r", encoding="utf-8") as f:
    source = f.read()
    # prevent subprocess execution
    source = re.sub(r'subprocess\.run\s*\(.*?\)', 'pass', source, flags=re.DOTALL)
    exec(source, namespace)

mii_list = namespace['mii']
pokemon_list = namespace['pokemon']
text_list = namespace['text']

root = ET.Element("characters")

locales = ["en_US", "ja_JP", "de_DE", "fr_FR", "es_ES", "it_IT"]
all_keys = ["dialog_1", "exchange_1", "mail_1", "mail_2", "dialog_2", "dialog_3", "name_1", "name_2", "name_from", "extra", "pad"]

for i in range(len(mii_list)):
    mii_hex = mii_list[i]
    pokemon_hex = pokemon_list[i] if i < len(pokemon_list) else ""
    text_data = text_list[i] if i < len(text_list) else {}
    
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
    
    char_keys = set()
    for loc, strings in text_data.items():
        if isinstance(strings, dict):
            for k in strings.keys():
                char_keys.add(k)
    
    ordered_keys = [k for k in all_keys if k in char_keys]
    for k in char_keys:
        if k not in ordered_keys:
            ordered_keys.append(k)
            
    if not ordered_keys:
        ordered_keys = all_keys # fallback
        
    for loc in locales:
        loc_node = ET.SubElement(text_node, loc)
        
        strings = text_data.get(loc, {})
        for k in ordered_keys:
            str_node = ET.SubElement(loc_node, "string", key=k)
            val = strings.get(k, "")
            if val:
                str_node.text = remove_invalid_xml_chars(val)
            else:
                str_node.text = ""

xmlstr = minidom.parseString(ET.tostring(root, 'utf-8')).toprettyxml(indent="  ")
with open("guest.xml", "w", encoding="utf-8") as f:
    f.write(xmlstr)
