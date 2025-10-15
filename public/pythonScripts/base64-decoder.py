# TITLE: 🔓 Base64 Decoder
# DESCRIPTION: Find and decode Base64 strings in files
# CATEGORY: Decoding
# AUTHOR: Sectoolbox

import base64
import re

file_path = '/uploads/sample.txt'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Convert to text
    text = data.decode('utf-8', errors='ignore')

    print("=== Base64 Decoder ===")
    print(f"File: {file_path}\n")

    # Find potential Base64 strings (at least 20 chars)
    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(b64_pattern, text)

    print(f"Found {len(matches)} potential Base64 strings\n")

    decoded_count = 0
    for i, match in enumerate(matches[:20], 1):  # Decode first 20
        try:
            # Attempt to decode
            decoded = base64.b64decode(match)

            # Check if decoded data is printable
            if all(32 <= b < 127 or b in [9, 10, 13] for b in decoded[:100]):
                decoded_text = decoded.decode('utf-8', errors='ignore')
                print(f"{i}. Original ({len(match)} chars):")
                print(f"   {match[:60]}{'...' if len(match) > 60 else ''}")
                print(f"   Decoded:")
                print(f"   {decoded_text[:100]}{'...' if len(decoded_text) > 100 else ''}")
                print()
                decoded_count += 1

        except Exception:
            continue

    if decoded_count == 0:
        print("⚠️  No valid Base64-encoded text found")
    else:
        print(f"✅ Successfully decoded {decoded_count} strings")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
