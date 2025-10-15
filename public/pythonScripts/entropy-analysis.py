# TITLE: 🧬 File Entropy Analyzer
# DESCRIPTION: Calculate entropy to detect encryption/packing
# CATEGORY: File Analysis
# AUTHOR: Sectoolbox

import math
from collections import Counter

def calculate_entropy(data):
    """Calculate Shannon entropy"""
    if not data:
        return 0
    entropy = 0
    counter = Counter(data)
    length = len(data)
    for count in counter.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return entropy

# Upload your file first
file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print("=== File Entropy Analysis ===")
    print(f"File: {file_path}")
    print(f"Size: {len(data):,} bytes\n")

    # Overall entropy
    total_entropy = calculate_entropy(data)
    print(f"Overall Entropy: {total_entropy:.4f}/8.0")

    # Interpretation
    if total_entropy > 7.5:
        print("⚠️  HIGH - Likely encrypted or compressed")
    elif total_entropy > 6.5:
        print("⚙️  MEDIUM - Possibly packed/obfuscated")
    else:
        print("✅ NORMAL - Plain/text data")

    # Block analysis (first 10 blocks)
    block_size = 4096
    print(f"\n=== Block Analysis (4KB blocks) ===")
    for i in range(0, min(len(data), block_size * 10), block_size):
        block = data[i:i+block_size]
        if block:
            block_entropy = calculate_entropy(block)
            status = "🔴" if block_entropy > 7.5 else "🟡" if block_entropy > 6.5 else "🟢"
            print(f"{status} Offset 0x{i:08x}: {block_entropy:.4f}")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
