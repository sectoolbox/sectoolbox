# TITLE: File Metadata Extractor
# DESCRIPTION: Extract embedded metadata and hidden data from files
# CATEGORY: Forensics
# AUTHOR: Sectoolbox

file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")

    # Check for common metadata markers
    print("\n=== Searching for Embedded Metadata ===")

    # EXIF markers (JPEG)
    if b'\xff\xe1' in data:
        print("Found: EXIF data marker (JPEG metadata)")
        exif_start = data.find(b'\xff\xe1')
        print(f"  Location: offset {exif_start}")

    # PNG metadata chunks
    if b'tEXt' in data or b'iTXt' in data or b'zTXt' in data:
        print("Found: PNG text chunks (metadata)")
        for chunk in [b'tEXt', b'iTXt', b'zTXt']:
            if chunk in data:
                pos = data.find(chunk)
                print(f"  {chunk.decode()}: offset {pos}")

    # PDF metadata
    if b'/Creator' in data or b'/Producer' in data or b'/Author' in data:
        print("Found: PDF metadata")
        if b'/Creator' in data:
            print(f"  /Creator found at offset {data.find(b'/Creator')}")
        if b'/Producer' in data:
            print(f"  /Producer found at offset {data.find(b'/Producer')}")
        if b'/Author' in data:
            print(f"  /Author found at offset {data.find(b'/Author')}")

    # Office document metadata
    if b'docProps' in data or b'meta.xml' in data:
        print("Found: Office document metadata (docProps)")

    # Check for hidden data patterns
    print("\n=== Hidden Data Analysis ===")

    # Check for data after EOF markers
    eof_markers = {
        b'\xff\xd9': 'JPEG EOF',
        b'IEND': 'PNG EOF',
        b'%%EOF': 'PDF EOF',
        b'</html>': 'HTML EOF'
    }

    for marker, desc in eof_markers.items():
        if marker in data:
            pos = data.rfind(marker)
            remaining = len(data) - pos - len(marker)
            if remaining > 0:
                print(f"Found: Data after {desc} ({remaining} bytes remaining)")
                print(f"  Marker at offset: {pos}")
                print(f"  Extra data starts at: {pos + len(marker)}")

    # Look for embedded archives
    archive_sigs = {
        b'PK\x03\x04': 'ZIP archive',
        b'Rar!\x1a\x07': 'RAR archive',
        b'\x1f\x8b\x08': 'GZIP data'
    }

    print("\n=== Embedded Files/Archives ===")
    for sig, desc in archive_sigs.items():
        count = data.count(sig)
        if count > 0:
            print(f"Found: {count} instance(s) of {desc}")
            # Show all positions
            pos = 0
            for i in range(count):
                pos = data.find(sig, pos)
                print(f"  Instance {i+1}: offset {pos}")
                pos += 1

    # Search for file paths
    print("\n=== Embedded File Paths ===")
    text = data.decode('utf-8', errors='ignore')

    # Windows paths
    import re
    win_paths = re.findall(r'[A-Z]:\\(?:[^\x00-\x1f\x7f<>:"|?*]+\\)*[^\x00-\x1f\x7f<>:"|?*]+', text)
    if win_paths:
        print(f"Windows paths found: {len(win_paths)}")
        for path in set(win_paths[:10]):
            print(f"  {path}")

    # Unix paths
    unix_paths = re.findall(r'/(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]+', text)
    unix_paths = [p for p in unix_paths if len(p) > 10]
    if unix_paths:
        print(f"Unix paths found: {len(unix_paths)}")
        for path in set(unix_paths[:10]):
            print(f"  {path}")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
