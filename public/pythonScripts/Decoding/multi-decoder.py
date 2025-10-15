# TITLE: Multi-Format Decoder
# DESCRIPTION: Automatically detect and decode Base64, Hex, Base32, and other encodings
# CATEGORY: Decoding
# AUTHOR: Sectoolbox

import base64
import re

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    text = data.decode('utf-8', errors='ignore')

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print("\n=== Multi-Format Decoder ===")

    decoded_results = []

    # Test 1: Base64
    try:
        # Clean whitespace
        clean_text = text.replace('\n', '').replace('\r', '').replace(' ', '')
        if len(clean_text) > 4 and set(clean_text).issubset(set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')):
            decoded_b64 = base64.b64decode(clean_text)
            printable = sum(1 for b in decoded_b64 if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable / len(decoded_b64) if len(decoded_b64) > 0 else 0

            if ratio > 0.5 or len(decoded_b64) < 100:
                decoded_results.append({
                    'format': 'Base64',
                    'data': decoded_b64,
                    'confidence': ratio,
                    'text': decoded_b64.decode('utf-8', errors='ignore')
                })
    except:
        pass

    # Test 2: Hex
    try:
        clean_hex = text.replace('\n', '').replace('\r', '').replace(' ', '').replace(':', '').replace('0x', '')
        if len(clean_hex) > 4 and len(clean_hex) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in clean_hex):
            decoded_hex = bytes.fromhex(clean_hex)
            printable = sum(1 for b in decoded_hex if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable / len(decoded_hex) if len(decoded_hex) > 0 else 0

            if ratio > 0.5 or len(decoded_hex) < 100:
                decoded_results.append({
                    'format': 'Hexadecimal',
                    'data': decoded_hex,
                    'confidence': ratio,
                    'text': decoded_hex.decode('utf-8', errors='ignore')
                })
    except:
        pass

    # Test 3: Base32
    try:
        clean_text = text.replace('\n', '').replace('\r', '').replace(' ', '').upper()
        if len(clean_text) > 4 and set(clean_text).issubset(set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')):
            decoded_b32 = base64.b32decode(clean_text)
            printable = sum(1 for b in decoded_b32 if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable / len(decoded_b32) if len(decoded_b32) > 0 else 0

            if ratio > 0.5 or len(decoded_b32) < 100:
                decoded_results.append({
                    'format': 'Base32',
                    'data': decoded_b32,
                    'confidence': ratio,
                    'text': decoded_b32.decode('utf-8', errors='ignore')
                })
    except:
        pass

    # Test 4: ASCII85 (Base85)
    try:
        if text.startswith('<~') and text.endswith('~>'):
            decoded_a85 = base64.a85decode(text)
            printable = sum(1 for b in decoded_a85 if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable / len(decoded_a85) if len(decoded_a85) > 0 else 0

            decoded_results.append({
                'format': 'ASCII85',
                'data': decoded_a85,
                'confidence': ratio,
                'text': decoded_a85.decode('utf-8', errors='ignore')
            })
    except:
        pass

    # Test 5: Binary string (e.g., "01010101")
    try:
        clean_bin = text.replace('\n', '').replace('\r', '').replace(' ', '')
        if len(clean_bin) > 8 and set(clean_bin).issubset(set('01')) and len(clean_bin) % 8 == 0:
            decoded_bin = bytes(int(clean_bin[i:i+8], 2) for i in range(0, len(clean_bin), 8))
            printable = sum(1 for b in decoded_bin if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable / len(decoded_bin) if len(decoded_bin) > 0 else 0

            if ratio > 0.5 or len(decoded_bin) < 100:
                decoded_results.append({
                    'format': 'Binary',
                    'data': decoded_bin,
                    'confidence': ratio,
                    'text': decoded_bin.decode('utf-8', errors='ignore')
                })
    except:
        pass

    # Test 6: Octal
    try:
        octal_pattern = r'\\[0-7]{3}'
        if re.search(octal_pattern, text):
            decoded_oct = re.sub(octal_pattern, lambda m: chr(int(m.group()[1:], 8)), text)
            decoded_results.append({
                'format': 'Octal escape sequences',
                'data': decoded_oct.encode(),
                'confidence': 0.8,
                'text': decoded_oct
            })
    except:
        pass

    # Show results
    if decoded_results:
        # Sort by confidence
        decoded_results.sort(key=lambda x: x['confidence'], reverse=True)

        print(f"\nSuccessfully decoded as {len(decoded_results)} format(s):\n")

        for i, result in enumerate(decoded_results, 1):
            print(f"[{i}] Format: {result['format']}")
            print(f"    Confidence: {result['confidence']*100:.1f}%")
            print(f"    Size: {len(result['data'])} bytes")

            preview = result['text'][:300]
            print(f"    Preview: {preview}")
            if len(result['text']) > 300:
                print(f"    ... ({len(result['text'])} total characters)")

            # Save to file
            output_file = f"/uploads/decoded_{result['format'].lower().replace(' ', '_')}.bin"
            with open(output_file, 'wb') as out:
                out.write(result['data'])
            print(f"    Saved to: {output_file}")
            print()

        # Check if best result contains flag pattern
        best = decoded_results[0]
        flag_patterns = [r'flag\{[^}]+\}', r'CTF\{[^}]+\}', r'FLAG\{[^}]+\}', r'\{[a-zA-Z0-9_]+\}']

        print("=== Flag Detection ===")
        found_flag = False
        for pattern in flag_patterns:
            matches = re.findall(pattern, best['text'], re.IGNORECASE)
            if matches:
                print(f"Potential flag(s) found:")
                for flag in matches:
                    print(f"  {flag}")
                found_flag = True

        if not found_flag:
            print("No flag patterns detected")

        # Recursive decode check
        print("\n=== Recursive Decode Check ===")
        current = best['text']
        layer = 1
        max_layers = 5

        while layer < max_layers:
            # Try base64 on current result
            try:
                clean = current.replace('\n', '').replace('\r', '').replace(' ', '')
                if len(clean) > 4:
                    next_decoded = base64.b64decode(clean)
                    printable = sum(1 for b in next_decoded if 32 <= b <= 126 or b in (9, 10, 13))
                    if printable / len(next_decoded) > 0.7:
                        layer += 1
                        current = next_decoded.decode('utf-8', errors='ignore')
                        print(f"Layer {layer}: Base64 decoded ({len(next_decoded)} bytes)")
                        print(f"  {current[:200]}")
                        continue
            except:
                pass

            break

        if layer > 1:
            print(f"\nTotal layers: {layer}")
            with open('/uploads/decoded_recursive.txt', 'w') as out:
                out.write(current)
            print("Saved final layer to: /uploads/decoded_recursive.txt")
        else:
            print("No additional encoding layers detected")

    else:
        print("Could not decode as any known format")
        print("\nPossibilities:")
        print("  - File is already decoded (raw binary or plaintext)")
        print("  - Using custom or uncommon encoding")
        print("  - Encrypted data")
        print("  - Try other specific decoder scripts")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
