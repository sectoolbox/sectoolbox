# TITLE: XOR Bruteforce Decoder
# DESCRIPTION: Try all single-byte XOR keys to decode encrypted data
# CATEGORY: Forensics
# AUTHOR: Sectoolbox

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print("\n=== XOR Bruteforce Analysis ===")

    # Try all possible single-byte XOR keys (0-255)
    results = []

    for key in range(256):
        # XOR decrypt
        decoded = bytes(b ^ key for b in data)

        # Count printable ASCII characters
        printable_count = sum(1 for b in decoded if 32 <= b <= 126)
        printable_ratio = printable_count / len(data)

        # Count common English characters if mostly printable
        if printable_ratio > 0.5:
            text = decoded.decode('ascii', errors='ignore')
            common_chars = sum(text.lower().count(c) for c in 'etaoinshrdlu ')
            common_ratio = common_chars / len(text) if len(text) > 0 else 0

            results.append({
                'key': key,
                'printable_ratio': printable_ratio,
                'common_ratio': common_ratio,
                'decoded': decoded,
                'text': text
            })

    # Sort by combined score
    results.sort(key=lambda x: x['printable_ratio'] * 0.5 + x['common_ratio'] * 0.5, reverse=True)

    # Show top 10 results
    print(f"Top 10 XOR key candidates:\n")

    for i, result in enumerate(results[:10], 1):
        key = result['key']
        print(f"Rank {i}: XOR Key = 0x{key:02x} (decimal {key}, char '{chr(key) if 32 <= key <= 126 else '?'}')")
        print(f"  Printable: {result['printable_ratio']*100:.1f}%")
        print(f"  Common chars: {result['common_ratio']*100:.1f}%")
        print(f"  Preview: {result['text'][:100]}")
        print()

    # Save best result
    if results:
        best = results[0]
        output_path = '/uploads/xor_decoded.bin'
        with open(output_path, 'wb') as out:
            out.write(best['decoded'])

        print(f"Best result saved to: {output_path}")
        print(f"XOR key used: 0x{best['key']:02x}")

        # Show more of the decoded text
        if best['printable_ratio'] > 0.7:
            print("\n=== Full Decoded Text (first 1000 chars) ===")
            print(best['text'][:1000])

    # Check for multi-byte XOR patterns
    print("\n=== Multi-byte XOR Detection ===")

    # Check for repeating key patterns (keys of length 2-8)
    for keylen in range(2, 9):
        if len(data) < keylen * 10:
            continue

        # Check if data has periodic patterns
        matches = 0
        for i in range(len(data) - keylen):
            if data[i] == data[i + keylen]:
                matches += 1

        pattern_ratio = matches / (len(data) - keylen)

        if pattern_ratio > 0.3:
            print(f"Possible {keylen}-byte repeating key (pattern ratio: {pattern_ratio*100:.1f}%)")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
