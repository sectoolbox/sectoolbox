# TITLE: 📦 ZIP Archive Analyzer
# DESCRIPTION: Analyze ZIP file structure and contents
# CATEGORY: Archive Analysis
# AUTHOR: Sectoolbox

import zipfile
from datetime import datetime

file_path = '/uploads/sample.zip'

try:
    with zipfile.ZipFile(file_path, 'r') as zf:
        print("=== ZIP Archive Analysis ===")
        print(f"File: {file_path}\n")

        # Get file list
        file_list = zf.namelist()
        print(f"Total Files: {len(file_list)}")

        # Calculate total size
        total_compressed = 0
        total_uncompressed = 0

        print("\n=== File List ===")
        print(f"{'Filename':<40} {'Size':>12} {'Compressed':>12} {'Ratio':>6}")
        print("-" * 75)

        for info in zf.infolist():
            total_compressed += info.compress_size
            total_uncompressed += info.file_size

            ratio = (1 - info.compress_size / info.file_size) * 100 if info.file_size > 0 else 0

            # Format filename (truncate if too long)
            name = info.filename
            if len(name) > 40:
                name = "..." + name[-37:]

            print(f"{name:<40} {info.file_size:>12,} {info.compress_size:>12,} {ratio:>5.1f}%")

        print("-" * 75)
        print(f"{'TOTAL':<40} {total_uncompressed:>12,} {total_compressed:>12,} "
              f"{(1 - total_compressed / total_uncompressed) * 100 if total_uncompressed > 0 else 0:>5.1f}%")

        # Check for suspicious patterns
        print("\n=== Security Analysis ===")
        suspicious = []

        for name in file_list:
            # Check for directory traversal
            if ".." in name or name.startswith("/"):
                suspicious.append(f"⚠️  Path traversal: {name}")

            # Check for executable files
            if name.lower().endswith(('.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs')):
                suspicious.append(f"⚠️  Executable: {name}")

            # Check for hidden files
            if '/..' in name or name.startswith('.'):
                suspicious.append(f"ℹ️  Hidden file: {name}")

        if suspicious:
            for item in suspicious[:10]:
                print(item)
        else:
            print("✅ No obvious suspicious patterns detected")

        # Extract and analyze first text file
        print("\n=== Content Preview ===")
        for info in zf.infolist()[:5]:
            if info.file_size < 1024 and info.file_size > 0:
                try:
                    content = zf.read(info.filename)
                    text = content.decode('utf-8', errors='ignore')
                    if text.isprintable() or all(c in text for c in '\n\r\t'):
                        print(f"\n📄 {info.filename}:")
                        print("-" * 40)
                        print(text[:200])
                        if len(text) > 200:
                            print("...")
                        break
                except:
                    continue

except zipfile.BadZipFile:
    print("❌ Error: Invalid ZIP file")
except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
