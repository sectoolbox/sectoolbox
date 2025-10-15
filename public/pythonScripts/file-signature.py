# TITLE: 🔖 File Signature Detector
# DESCRIPTION: Identify file type by magic bytes
# CATEGORY: File Analysis
# AUTHOR: Sectoolbox

def identify_file_type(data):
    """Identify file type by magic bytes (file signature)"""

    # Common file signatures
    signatures = [
        (b'\x50\x4B\x03\x04', 'ZIP Archive'),
        (b'\x50\x4B\x05\x06', 'ZIP Archive (empty)'),
        (b'\x50\x4B\x07\x08', 'ZIP Archive (spanned)'),
        (b'\x4D\x5A', 'PE Executable (EXE/DLL)'),
        (b'\x7F\x45\x4C\x46', 'ELF Executable'),
        (b'\xFF\xD8\xFF', 'JPEG Image'),
        (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 'PNG Image'),
        (b'GIF87a', 'GIF Image (87a)'),
        (b'GIF89a', 'GIF Image (89a)'),
        (b'\x42\x4D', 'BMP Image'),
        (b'\x49\x49\x2A\x00', 'TIFF Image (little-endian)'),
        (b'\x4D\x4D\x00\x2A', 'TIFF Image (big-endian)'),
        (b'%PDF-', 'PDF Document'),
        (b'\x25\x21\x50\x53', 'PostScript'),
        (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', 'MS Office Document (DOC/XLS/PPT)'),
        (b'PK\x03\x04\x14\x00\x06\x00', 'MS Office (OOXML)'),
        (b'Rar!\x1A\x07', 'RAR Archive (v4)'),
        (b'Rar!\x1A\x07\x01\x00', 'RAR Archive (v5)'),
        (b'\x37\x7A\xBC\xAF\x27\x1C', '7-Zip Archive'),
        (b'\x1F\x8B\x08', 'GZIP Archive'),
        (b'BZh', 'BZIP2 Archive'),
        (b'\xFD\x37\x7A\x58\x5A\x00', 'XZ Archive'),
        (b'\x52\x61\x72\x21', 'RAR Archive'),
        (b'\x75\x73\x74\x61\x72', 'TAR Archive'),
        (b'\x4F\x67\x67\x53', 'OGG Media'),
        (b'ID3', 'MP3 Audio'),
        (b'\xFF\xFB', 'MP3 Audio (no ID3)'),
        (b'fLaC', 'FLAC Audio'),
        (b'RIFF', 'RIFF Container (WAV/AVI)'),
        (b'\x00\x00\x00\x14\x66\x74\x79\x70', 'MP4 Video'),
        (b'\x00\x00\x00\x18\x66\x74\x79\x70', 'MP4 Video'),
        (b'\x1A\x45\xDF\xA3', 'Matroska/WebM Video'),
        (b'FLV', 'Flash Video'),
        (b'\x30\x26\xB2\x75\x8E\x66\xCF\x11', 'WMA/WMV'),
        (b'SQLite format 3', 'SQLite Database'),
        (b'\x4C\x00\x00\x00', 'Windows Shortcut (LNK)'),
        (b'\xCA\xFE\xBA\xBE', 'Java Class File'),
        (b'\x4D\x45\x54\x41\x2D\x49\x4E\x46', 'Java JAR'),
        (b'\xED\xAB\xEE\xDB', 'RPM Package'),
        (b'!<arch>', 'Debian Package'),
        (b'\x1F\x9D', 'Compress (.Z)'),
        (b'\x1F\xA0', 'Compress (.Z)'),
        (b'BM', 'BMP Image'),
        (b'\x00\x00\x01\x00', 'ICO Image'),
        (b'\x00\x00\x02\x00', 'CUR Cursor'),
        (b'\x52\x49\x46\x46', 'RIFF (WAV/AVI/WebP)'),
    ]

    # Check signatures
    matches = []
    for sig, desc in signatures:
        if data.startswith(sig):
            matches.append(desc)

    # Check for text files
    try:
        text = data[:1024].decode('utf-8')
        if text.isprintable() or all(c in text for c in '\n\r\t'):
            if '<html' in text.lower() or '<!doctype' in text.lower():
                matches.append('HTML Document')
            elif '<?xml' in text.lower():
                matches.append('XML Document')
            elif data.startswith(b'#!'):
                matches.append('Script/Shell Script')
            elif text.strip():
                matches.append('Text File')
    except:
        pass

    return matches if matches else ['Unknown']

# Upload your file first
file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print("=== File Signature Detector ===")
    print(f"File: {file_path}")
    print(f"Size: {len(data):,} bytes\n")

    # Display first 64 bytes as hex
    print("First 64 bytes (hex):")
    hex_dump = ' '.join(f'{b:02x}' for b in data[:64])
    for i in range(0, len(hex_dump), 48):
        print(f"  {hex_dump[i:i+48]}")

    print("\nFirst 64 bytes (ASCII):")
    ascii_dump = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:64])
    for i in range(0, len(ascii_dump), 64):
        print(f"  {ascii_dump[i:i+64]}")

    # Identify file type
    print("\n=== File Type Detection ===")
    file_types = identify_file_type(data)

    for ft in file_types:
        print(f"✓ {ft}")

    # Additional analysis
    print("\n=== Additional Info ===")
    print(f"Null bytes: {data.count(b'\\x00'):,} ({data.count(b'\\x00')/len(data)*100:.1f}%)")

    # Check if mostly ASCII
    ascii_count = sum(1 for b in data[:10000] if 32 <= b < 127 or b in [9, 10, 13])
    print(f"ASCII characters: {ascii_count/min(len(data), 10000)*100:.1f}%")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
