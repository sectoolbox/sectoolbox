# TITLE: Base64 Decoder
# DESCRIPTION: Find and decode all Base64 encoded strings in file
# CATEGORY: Decoding
# AUTHOR: Sectoolbox

import base64
import re

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Try to decode as text
    text = data.decode('utf-8', errors='ignore')

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print("\n=== Base64 Decoding ===")

    # Pattern for base64 strings (min 8 chars)
    # Valid base64 chars: A-Z, a-z, 0-9, +, /, with optional = padding
    base64_pattern = r'[A-Za-z0-9+/]{8,}={0,2}'

    matches = re.findall(base64_pattern, text)

    print(f"Found {len(matches)} potential Base64 strings\n")

    decoded_items = []

    for i, match in enumerate(matches, 1):
        try:
            # Try to decode
            decoded = base64.b64decode(match)

            # Check if decoded data is meaningful
            printable_count = sum(1 for b in decoded if 32 <= b <= 126 or b in (9, 10, 13))
            is_likely_valid = printable_count / len(decoded) > 0.75 if len(decoded) > 0 else False

            if is_likely_valid or len(decoded) < 100:
                decoded_text = decoded.decode('utf-8', errors='ignore')

                decoded_items.append({
                    'index': i,
                    'original': match,
                    'decoded': decoded,
                    'text': decoded_text,
                    'printable_ratio': printable_count / len(decoded) if len(decoded) > 0 else 0
                })

        except Exception:
            # Not valid base64, skip
            continue

    # Show all decoded items
    if decoded_items:
        print(f"Successfully decoded {len(decoded_items)} Base64 strings:\n")

        for item in decoded_items:
            print(f"[{item['index']}] Original ({len(item['original'])} chars):")
            print(f"    {item['original'][:80]}{'...' if len(item['original']) > 80 else ''}")
            print(f"    Decoded ({len(item['decoded'])} bytes, {item['printable_ratio']*100:.1f}% printable):")

            if item['printable_ratio'] > 0.5:
                # Show as text
                preview = item['text'][:200]
                print(f"    {preview}{'...' if len(item['text']) > 200 else ''}")
            else:
                # Show as hex
                hex_preview = ' '.join(f'{b:02x}' for b in item['decoded'][:32])
                print(f"    Hex: {hex_preview}{'...' if len(item['decoded']) > 32 else ''}")

            print()

        # Try to decode the entire file as base64
        print("=== Attempting to decode entire file ===")
        try:
            # Remove whitespace and newlines
            clean_data = text.replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '')

            decoded_full = base64.b64decode(clean_data)
            print(f"Success! Entire file is valid Base64")
            print(f"Decoded size: {len(decoded_full)} bytes")

            # Save decoded file
            output_path = '/uploads/base64_decoded.bin'
            with open(output_path, 'wb') as out:
                out.write(decoded_full)

            print(f"Saved to: {output_path}")

            # Show preview
            printable = sum(1 for b in decoded_full if 32 <= b <= 126)
            if printable / len(decoded_full) > 0.7:
                print(f"\nDecoded text preview:")
                print(decoded_full[:500].decode('utf-8', errors='ignore'))
            else:
                print(f"\nDecoded hex preview:")
                print(' '.join(f'{b:02x}' for b in decoded_full[:64]))

        except Exception as e:
            print(f"Entire file is not valid Base64: {e}")

    else:
        print("No valid Base64 strings found")
        print("\nNote: This tool looks for Base64-encoded data")
        print("If you expect Base64 but nothing was found, the data might be:")
        print("  - Using a different encoding (hex, base32, etc.)")
        print("  - Encrypted or obfuscated")
        print("  - Not properly formatted")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
