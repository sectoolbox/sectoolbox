# TITLE: Hex Decoder
# DESCRIPTION: Find and decode hexadecimal encoded strings
# CATEGORY: Decoding
# AUTHOR: Sectoolbox

import re

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Try to decode as text
    text = data.decode('utf-8', errors='ignore')

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print("\n=== Hex Decoding ===")

    # Pattern for hex strings (pairs of hex digits, min 8 chars = 4 bytes)
    # With optional spaces, colons, or no separators
    hex_patterns = [
        (r'\b([0-9a-fA-F]{2}[:\s]?){4,}', 'Hex with separators'),
        (r'\b[0-9a-fA-F]{8,}\b', 'Continuous hex'),
        (r'0x[0-9a-fA-F]{8,}', 'Hex with 0x prefix'),
        (r'\\x[0-9a-fA-F]{2}', 'Escaped hex bytes (\\x)')
    ]

    all_decoded = []

    for pattern, desc in hex_patterns:
        matches = re.findall(pattern, text)

        if not matches:
            continue

        print(f"\n{desc}: Found {len(matches)} matches")

        for i, match in enumerate(matches[:20], 1):  # Limit to first 20
            try:
                # Clean the match
                if isinstance(match, tuple):
                    match = match[0]

                # Remove separators and prefixes
                clean_hex = match.replace(' ', '').replace(':', '').replace('\\x', '').replace('0x', '')

                # Must be even length
                if len(clean_hex) % 2 != 0:
                    continue

                # Decode
                decoded = bytes.fromhex(clean_hex)

                # Check if decoded data is meaningful
                printable_count = sum(1 for b in decoded if 32 <= b <= 126 or b in (9, 10, 13))
                printable_ratio = printable_count / len(decoded) if len(decoded) > 0 else 0

                if printable_ratio > 0.5 or len(decoded) < 50:
                    decoded_text = decoded.decode('utf-8', errors='ignore')

                    all_decoded.append({
                        'type': desc,
                        'original': match[:100],
                        'decoded': decoded,
                        'text': decoded_text,
                        'printable_ratio': printable_ratio
                    })

            except Exception as e:
                continue

    # Show all decoded items
    if all_decoded:
        print(f"\n=== Successfully Decoded Items ({len(all_decoded)}) ===\n")

        for i, item in enumerate(all_decoded, 1):
            print(f"[{i}] Type: {item['type']}")
            print(f"    Original: {item['original']}{'...' if len(str(item['original'])) > 100 else ''}")
            print(f"    Decoded ({len(item['decoded'])} bytes, {item['printable_ratio']*100:.1f}% printable):")

            if item['printable_ratio'] > 0.5:
                preview = item['text'][:200]
                print(f"    Text: {preview}{'...' if len(item['text']) > 200 else ''}")
            else:
                hex_preview = ' '.join(f'{b:02x}' for b in item['decoded'][:32])
                print(f"    Hex: {hex_preview}{'...' if len(item['decoded']) > 32 else ''}")

            print()

    # Try to decode entire file as hex
    print("=== Attempting to decode entire file as hex ===")
    try:
        # Remove all whitespace
        clean_text = text.replace('\n', '').replace('\r', '').replace(' ', '').replace('\t', '').replace(':', '')

        # Remove 0x prefix if present
        if clean_text.startswith('0x'):
            clean_text = clean_text[2:]

        # Try to decode
        if len(clean_text) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in clean_text):
            decoded_full = bytes.fromhex(clean_text)

            print(f"Success! Entire file is valid hex")
            print(f"Decoded size: {len(decoded_full)} bytes")

            # Save decoded file
            output_path = '/uploads/hex_decoded.bin'
            with open(output_path, 'wb') as out:
                out.write(decoded_full)

            print(f"Saved to: {output_path}")

            # Show preview
            printable = sum(1 for b in decoded_full if 32 <= b <= 126)
            if printable / len(decoded_full) > 0.7:
                print(f"\nDecoded text preview:")
                print(decoded_full[:500].decode('utf-8', errors='ignore'))
            else:
                print(f"\nDecoded data preview (hex):")
                print(' '.join(f'{b:02x}' for b in decoded_full[:64]))

                # Check for file signatures
                if decoded_full.startswith(b'\xff\xd8\xff'):
                    print("\nDetected: JPEG image")
                elif decoded_full.startswith(b'\x89PNG'):
                    print("\nDetected: PNG image")
                elif decoded_full.startswith(b'PK\x03\x04'):
                    print("\nDetected: ZIP archive")
                elif decoded_full.startswith(b'%PDF'):
                    print("\nDetected: PDF document")

        else:
            print("Entire file is not valid hex encoding")

    except Exception as e:
        print(f"Failed to decode entire file: {e}")

    if not all_decoded and not any(matches for pattern, desc in hex_patterns for matches in [re.findall(pattern, text)] if matches):
        print("\nNo hex-encoded data found")
        print("The file might be:")
        print("  - Binary data (not text-encoded)")
        print("  - Using a different encoding (base64, base32, etc.)")
        print("  - Already decoded")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
