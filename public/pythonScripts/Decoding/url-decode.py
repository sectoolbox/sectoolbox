# TITLE: URL Decoder
# DESCRIPTION: Decode URL-encoded (percent-encoded) strings
# CATEGORY: Decoding
# AUTHOR: Sectoolbox

from urllib.parse import unquote, unquote_plus

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Decode as text
    text = data.decode('utf-8', errors='ignore')

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")

    # Check if file contains URL encoding
    if '%' not in text:
        print("\nNo URL encoding detected (no '%' characters found)")
        print("File does not appear to be URL-encoded")
    else:
        print(f"\n=== URL Decoding ===")
        print(f"Found {text.count('%')} percent signs")

        # Standard URL decode
        print("\n[1] Standard URL decode:")
        decoded_standard = unquote(text)
        print(decoded_standard[:1000])
        if len(decoded_standard) > 1000:
            print(f"... ({len(decoded_standard)} total characters)")

        # URL decode with plus to space
        print("\n[2] URL decode (+ to space):")
        decoded_plus = unquote_plus(text)
        print(decoded_plus[:1000])
        if len(decoded_plus) > 1000:
            print(f"... ({len(decoded_plus)} total characters)")

        # Recursive decode (multiple layers)
        print("\n[3] Recursive decode (multiple layers):")
        current = text
        layer = 0
        max_layers = 10

        while '%' in current and layer < max_layers:
            previous = current
            current = unquote(current)
            layer += 1

            if current == previous:
                break

            print(f"\n  Layer {layer}:")
            print(f"  {current[:200]}")
            if len(current) > 200:
                print(f"  ... ({len(current)} total characters)")

        if layer > 0:
            print(f"\n  Total layers decoded: {layer}")

        # Save decoded versions
        with open('/uploads/url_decoded.txt', 'w', encoding='utf-8') as out:
            out.write(decoded_standard)
        print("\n[+] Standard decode saved to: /uploads/url_decoded.txt")

        if decoded_plus != decoded_standard:
            with open('/uploads/url_decoded_plus.txt', 'w', encoding='utf-8') as out:
                out.write(decoded_plus)
            print("[+] Plus-to-space decode saved to: /uploads/url_decoded_plus.txt")

        if layer > 1:
            with open('/uploads/url_decoded_recursive.txt', 'w', encoding='utf-8') as out:
                out.write(current)
            print(f"[+] Recursive decode ({layer} layers) saved to: /uploads/url_decoded_recursive.txt")

        # Analyze decoded content
        print("\n=== Analysis ===")

        # Check for common patterns in decoded data
        final_decoded = current if layer > 0 else decoded_standard

        patterns = {
            'http://': 'HTTP URLs',
            'https://': 'HTTPS URLs',
            'SELECT': 'SQL query',
            'script': 'JavaScript/HTML',
            '<': 'HTML/XML tags',
            'flag{': 'CTF flag format',
            'CTF{': 'CTF flag format',
            '{': 'JSON data'
        }

        found_patterns = []
        for pattern, description in patterns.items():
            count = final_decoded.lower().count(pattern.lower())
            if count > 0:
                found_patterns.append(f"{description} ({count}x)")

        if found_patterns:
            print("Detected patterns in decoded data:")
            for p in found_patterns:
                print(f"  - {p}")
        else:
            print("No specific patterns detected in decoded data")

        # Check for double encoding
        if text.count('%25') > 0:
            print(f"\nWarning: Found {text.count('%25')} instances of '%25' (encoded '%')")
            print("This suggests double or multiple URL encoding")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
