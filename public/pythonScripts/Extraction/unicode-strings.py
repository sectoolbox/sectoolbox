# TITLE: Unicode String Extractor
# DESCRIPTION: Extract both ASCII and Unicode (UTF-16LE) strings from file
# CATEGORY: Extraction
# AUTHOR: Sectoolbox

import re

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")

    # Extract ASCII strings (printable chars, min length 4)
    ascii_strings = re.findall(rb'[ -~]{4,}', data)

    print(f"\n=== ASCII Strings ({len(ascii_strings)}) ===")
    for s in ascii_strings:
        print(s.decode('ascii', errors='ignore'))

    # Extract UTF-16LE strings (common in Windows binaries)
    # Pattern: printable ASCII followed by null bytes
    utf16_pattern = rb'(?:[ -~]\x00){4,}'
    utf16_strings = re.findall(utf16_pattern, data)

    print(f"\n=== UTF-16LE Strings ({len(utf16_strings)}) ===")
    for s in utf16_strings:
        try:
            decoded = s.decode('utf-16-le', errors='ignore')
            if decoded.strip():
                print(decoded)
        except:
            pass

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
