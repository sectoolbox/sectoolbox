# TITLE: 🔍 File Hash Calculator
# DESCRIPTION: Calculate MD5, SHA1, SHA256 hashes of uploaded files
# CATEGORY: File Analysis
# AUTHOR: Sectoolbox

import hashlib

# Upload your file first
file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print("=== File Hash Calculator ===")
    print(f"File: {file_path}")
    print(f"Size: {len(data):,} bytes ({len(data)/1024:.2f} KB)\n")

    # Calculate hashes
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    print(f"MD5:    {md5}")
    print(f"SHA1:   {sha1}")
    print(f"SHA256: {sha256}")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
