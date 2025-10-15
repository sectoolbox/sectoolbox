# TITLE: Steganography Detector
# DESCRIPTION: Detect potential steganography and LSB patterns in files
# CATEGORY: Forensics
# AUTHOR: Sectoolbox

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")

    # Check for LSB (Least Significant Bit) patterns
    print("\n=== LSB Analysis ===")

    if len(data) > 100:
        # Extract LSBs from each byte
        lsbs = [byte & 1 for byte in data]

        # Count 0s and 1s
        zeros = lsbs.count(0)
        ones = lsbs.count(1)
        total = len(lsbs)

        print(f"LSB distribution:")
        print(f"  0s: {zeros} ({zeros/total*100:.2f}%)")
        print(f"  1s: {ones} ({ones/total*100:.2f}%)")

        # Check for suspicious patterns
        if abs(zeros - ones) < total * 0.1:
            print("  Analysis: BALANCED distribution (possible LSB steganography)")
        else:
            print("  Analysis: Normal distribution")

        # Try to extract LSB data as bytes
        if len(lsbs) >= 8:
            lsb_bytes = []
            for i in range(0, len(lsbs) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | lsbs[i + j]
                lsb_bytes.append(byte_val)

            # Check if LSB data looks like meaningful content
            printable = sum(1 for b in lsb_bytes[:100] if 32 <= b <= 126)
            if printable > 50:
                print(f"\n  LSB data contains {printable}% printable ASCII in first 100 bytes")
                print("  Possible hidden message detected!")

                # Try to decode as text
                lsb_text = bytes(lsb_bytes[:200]).decode('ascii', errors='ignore')
                if len(lsb_text) > 10:
                    print(f"\n  First 200 bytes of LSB data:")
                    print(f"  {lsb_text}")

    # Check for multiple file signatures
    print("\n=== Multiple File Detection ===")

    signatures = [
        (b'\xff\xd8\xff', 'JPEG'),
        (b'\x89PNG', 'PNG'),
        (b'GIF8', 'GIF'),
        (b'PK\x03\x04', 'ZIP'),
        (b'Rar!', 'RAR'),
        (b'%PDF', 'PDF'),
        (b'\x1f\x8b', 'GZIP')
    ]

    found_sigs = []
    for sig, name in signatures:
        pos = 0
        positions = []
        while True:
            pos = data.find(sig, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1

        if positions:
            found_sigs.append((name, positions))

    if len(found_sigs) > 1:
        print("Multiple file signatures detected (possible file concatenation):")
        for name, positions in found_sigs:
            print(f"  {name}: {len(positions)} occurrence(s) at {positions[:5]}")
    elif found_sigs:
        print("Single file type detected")

    # Check for trailing data
    print("\n=== Trailing Data Analysis ===")

    # Check for null padding followed by data
    if b'\x00' * 100 in data:
        null_pos = data.find(b'\x00' * 100)
        # Check if there's non-null data after
        remaining = data[null_pos:]
        non_null_after = len(remaining) - len(remaining.lstrip(b'\x00'))

        if non_null_after < len(remaining):
            print(f"Found: Large null padding at offset {null_pos}")
            print(f"  Data resumes at offset: {null_pos + non_null_after}")
            print(f"  Possible hidden data after null padding")

    # Statistical anomaly detection
    print("\n=== Statistical Anomalies ===")

    chunk_size = len(data) // 10 if len(data) > 1000 else 100
    if chunk_size > 0:
        entropies = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i+chunk_size]
            if len(chunk) < chunk_size // 2:
                continue

            # Simple entropy calculation
            from collections import Counter
            counts = Counter(chunk)
            entropy = 0
            for count in counts.values():
                p = count / len(chunk)
                if p > 0:
                    import math
                    entropy -= p * math.log2(p)
            entropies.append((i, entropy))

        if len(entropies) > 1:
            avg_entropy = sum(e for _, e in entropies) / len(entropies)
            print(f"Average entropy: {avg_entropy:.2f}")

            # Find chunks with significantly different entropy
            for offset, entropy in entropies:
                if abs(entropy - avg_entropy) > 1.5:
                    print(f"  Anomaly at offset {offset}: entropy {entropy:.2f} (diff: {entropy - avg_entropy:+.2f})")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
