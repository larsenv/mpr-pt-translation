#!/usr/bin/env python3
"""
Rosetta Stone translation mapper.

For each locale XX_XX (excluding ja_JP, en_US, en_GB, es_ES):
  For each txt file in usplat/00000005.app/es_ES/msg/:
    For each message (id1, content1) in that file:
      Search for content1 in old/europe/00000005.app/es_ES/msg/<same file>
      If found with id2:
        Look up id2 in old/europe/00000005.app/XX_XX/msg/<same file>
        Write that translation to usplat/00000005.app/XX_XX/msg/<same file> with id1
      If not found:
        Write "TRANSLATION NEEDED" with id1
"""

import os
import re

BASE = '/Volumes/SSD/larsen/Downloads/mpr-pt-translation'
USPLAT = os.path.join(BASE, 'usplat/00000005.app')
OLD_EU = os.path.join(BASE, 'old/europe/00000005.app')

SKIP_LOCALES = {'ja_JP', 'en_US', 'en_GB', 'es_ES', 'EUR', 'USA', 'nl_NL'}
SKIP_FILES = {'debug.bmg.txt'}

def parse_bmg(filepath):
    """Parse a BMG txt file. Returns (header_lines, {id_lower: (full_id_line, content_lines)})."""
    if not os.path.exists(filepath):
        return [], {}
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    header = []
    messages = {}  # id_lower -> (id_line_with_attrs, [content_lines_including_id_line])
    current_id = None
    current_id_key = None
    current_block = []

    for line in lines:
        m = re.match(r'^(\s*([0-9a-fA-F]+)\s*(?:\[.*?\])?\s*=.*)', line)
        if m:
            if current_id_key is not None:
                messages[current_id_key] = current_block
            current_id_key = m.group(2).lower().lstrip('0') or '0'
            current_block = [line]
        else:
            if current_id_key is not None:
                current_block.append(line)
            else:
                header.append(line)

    if current_id_key is not None:
        messages[current_id_key] = current_block

    return header, messages


def extract_content(block):
    """Extract the pure text content from a message block (strip id/attrs, join continuation lines)."""
    if not block:
        return ''
    # First line: everything after '='
    first = block[0]
    idx = first.index('=')
    text = first[idx+1:].strip()
    # Continuation lines start with \t+
    for line in block[1:]:
        stripped = line.strip()
        if stripped.startswith('+'):
            text += ' ' + stripped[1:].strip()
    return text


def extract_id_and_attrs(block):
    """Extract the raw ID line prefix (with spacing and attributes) from a block."""
    if not block:
        return None
    m = re.match(r'^(\s*[0-9a-fA-F]+\s*(?:\[.*?\])?)\s*=', block[0])
    if m:
        return m.group(1)
    return None


def write_bmg(filepath, header, messages_ordered):
    """Write a BMG file. messages_ordered is a list of (id_key, block_lines)."""
    with open(filepath, 'w', encoding='utf-8') as f:
        for h in header:
            f.write(h)
        for id_key, block in messages_ordered:
            for line in block:
                f.write(line)


# Build content->id mapping for old/europe es_ES
def build_content_to_id_map(filepath):
    """Build a map from normalized content -> id_key for an old europe es_ES file."""
    _, messages = parse_bmg(filepath)
    content_map = {}
    for id_key, block in messages.items():
        content = extract_content(block)
        # Normalize whitespace for matching
        normalized = ' '.join(content.split())
        if normalized and normalized not in content_map:
            content_map[normalized] = id_key
    return content_map


# Get list of target locales
target_locales = []
for name in os.listdir(USPLAT):
    full = os.path.join(USPLAT, name)
    if os.path.isdir(full) and name not in SKIP_LOCALES:
        target_locales.append(name)

target_locales.sort()
print(f"Target locales: {target_locales}")

# Get list of txt files from es_ES
es_msg_dir = os.path.join(USPLAT, 'es_ES', 'msg')
txt_files = [f for f in os.listdir(es_msg_dir) if f.endswith('.bmg.txt') and f not in SKIP_FILES]
txt_files.sort()
print(f"Files to process: {txt_files}")

stats = {'matched': 0, 'not_found': 0, 'no_old_translation': 0, 'total': 0}

for locale in target_locales:
    print(f"\n=== Processing locale: {locale} ===")
    locale_msg_dir = os.path.join(USPLAT, locale, 'msg')

    for txt_file in txt_files:
        us_es_path = os.path.join(USPLAT, 'es_ES', 'msg', txt_file)
        old_eu_es_path = os.path.join(OLD_EU, 'es_ES', 'msg', txt_file)
        old_eu_locale_path = os.path.join(OLD_EU, locale, 'msg', txt_file)
        target_path = os.path.join(locale_msg_dir, txt_file)

        # Parse the US es_ES file (source of truth for IDs)
        us_es_header, us_es_msgs = parse_bmg(us_es_path)
        if not us_es_msgs:
            continue

        # Build content->id map from old europe es_ES
        old_es_content_map = build_content_to_id_map(old_eu_es_path)

        # Parse old europe locale file
        _, old_locale_msgs = parse_bmg(old_eu_locale_path)

        # Get the header from the existing target file if it exists, otherwise from es_ES
        if os.path.exists(target_path):
            target_header, _ = parse_bmg(target_path)
        else:
            target_header = us_es_header[:]

        # Build the new messages
        new_messages = []
        for id_key in sorted(us_es_msgs.keys(), key=lambda x: int(x, 16)):
            block = us_es_msgs[id_key]
            content = extract_content(block)
            normalized = ' '.join(content.split())
            stats['total'] += 1

            # Get the id line prefix from the US es_ES (preserves spacing and attrs)
            id_prefix = extract_id_and_attrs(block)

            # Search for this content in old europe es_ES
            old_eu_id = old_es_content_map.get(normalized)

            if old_eu_id is not None and old_eu_id in old_locale_msgs:
                # Found a match! Use the old locale's translation
                old_block = old_locale_msgs[old_eu_id]
                # Rewrite the block with the new ID but old content
                old_content_after_eq = old_block[0][old_block[0].index('='):]
                new_block = [f"{id_prefix} {old_content_after_eq}"]
                new_block.extend(old_block[1:])
                new_messages.append((id_key, new_block))
                stats['matched'] += 1
            elif old_eu_id is not None:
                # Found in old es_ES but no translation exists for this locale
                new_block = [f"{id_prefix} = TRANSLATION NEEDED\n"]
                new_messages.append((id_key, new_block))
                stats['no_old_translation'] += 1
            else:
                # Not found in old europe es_ES at all
                new_block = [f"{id_prefix} = TRANSLATION NEEDED\n"]
                new_messages.append((id_key, new_block))
                stats['not_found'] += 1

        # Write the file
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        write_bmg(target_path, target_header, new_messages)
        print(f"  Wrote {target_path} ({len(new_messages)} messages)")

print(f"\n=== Stats ===")
print(f"Total messages processed: {stats['total']}")
print(f"Matched with old translations: {stats['matched']}")
print(f"Old es_ES match but no locale translation: {stats['no_old_translation']}")
print(f"Not found in old es_ES: {stats['not_found']}")
