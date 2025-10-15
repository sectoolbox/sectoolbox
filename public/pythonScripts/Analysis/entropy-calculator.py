# TITLE: Entropy Calculator
# DESCRIPTION: Calculate file entropy to detect encryption, compression, or randomness
# CATEGORY: Analysis
# AUTHOR: Sectoolbox

import math
from collections import Counter

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    if len(data) == 0:
        print("Error: File is empty")
    else:
        # Calculate byte frequency
        byte_counts = Counter(data)

        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)

        print(f"File: {file_path}")
        print(f"Size: {len(data)} bytes")
        print(f"Unique bytes: {len(byte_counts)}/256")
        print(f"Entropy: {entropy:.6f} bits per byte")
        print()

        # Interpretation
        if entropy > 7.5:
            print("Analysis: HIGH entropy (likely encrypted or compressed)")
        elif entropy > 6.0:
            print("Analysis: MEDIUM entropy (possibly packed or encoded)")
        elif entropy > 4.0:
            print("Analysis: MODERATE entropy (mixed data)")
        else:
            print("Analysis: LOW entropy (plaintext or repetitive data)")

        # Show most common bytes
        print("\n=== Top 10 Most Common Bytes ===")
        for byte_val, count in byte_counts.most_common(10):
            percentage = (count / len(data)) * 100
            char_repr = chr(byte_val) if 32 <= byte_val <= 126 else '.'
            print(f"0x{byte_val:02x} ('{char_repr}'): {count:8d} ({percentage:6.2f}%)")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
