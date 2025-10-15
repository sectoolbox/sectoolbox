# TITLE: File Hash Calculator
# DESCRIPTION: Calculate MD5, SHA1, SHA256, SHA512 hashes of uploaded file
# CATEGORY: Analysis
# AUTHOR: Sectoolbox

import hashlib

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print("\n=== Hashes ===")
    print(f"MD5:    {hashlib.md5(data).hexdigest()}")
    print(f"SHA1:   {hashlib.sha1(data).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")
    print(f"SHA512: {hashlib.sha512(data).hexdigest()}")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
