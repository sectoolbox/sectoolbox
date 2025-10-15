# TITLE: File Signature Detector
# DESCRIPTION: Identify file type by magic bytes (header signatures)
# CATEGORY: Analysis
# AUTHOR: Sectoolbox

file_path = '/uploads/sample.bin'

# Common file signatures
signatures = {
    b'\xFF\xD8\xFF': 'JPEG image',
    b'\x89PNG\r\n\x1a\n': 'PNG image',
    b'GIF87a': 'GIF image (87a)',
    b'GIF89a': 'GIF image (89a)',
    b'BM': 'BMP image',
    b'RIFF': 'RIFF container (WAV/AVI/WEBP)',
    b'PK\x03\x04': 'ZIP archive',
    b'PK\x05\x06': 'ZIP archive (empty)',
    b'PK\x07\x08': 'ZIP archive (spanned)',
    b'\x1f\x8b\x08': 'GZIP compressed',
    b'Rar!\x1a\x07': 'RAR archive',
    b'7z\xbc\xaf\x27\x1c': '7-Zip archive',
    b'%PDF': 'PDF document',
    b'\x50\x4B\x03\x04': 'ZIP/JAR/DOCX/XLSX',
    b'MZ': 'PE/DOS executable',
    b'\x7fELF': 'ELF executable',
    b'\xca\xfe\xba\xbe': 'Mach-O binary (32-bit)',
    b'\xcf\xfa\xed\xfe': 'Mach-O binary (64-bit)',
    b'\xfe\xed\xfa\xce': 'Mach-O binary (reverse 32-bit)',
    b'\xfe\xed\xfa\xcf': 'Mach-O binary (reverse 64-bit)',
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'Microsoft Office (old format)',
    b'ftyp': 'MP4/M4V video (at offset 4)',
    b'\x00\x00\x01\xBA': 'MPEG video',
    b'\x00\x00\x01\xB3': 'MPEG video',
    b'ID3': 'MP3 audio (with ID3)',
    b'\xff\xfb': 'MP3 audio',
    b'\xff\xf3': 'MP3 audio',
    b'\xff\xf2': 'MP3 audio',
    b'OggS': 'OGG container',
    b'fLaC': 'FLAC audio',
    b'<\?xml': 'XML document',
    b'<!DOCTYPE': 'HTML/XML document',
    b'<html': 'HTML document',
    b'\x1f\x9d': 'Compressed archive (compress)',
    b'\x1f\xa0': 'Compressed archive (LZH)',
    b'SQLite format 3': 'SQLite database',
    b'\x00\x00\x00\x0cjP  \r\n\x87\n': 'JPEG 2000',
    b'-----BEGIN': 'PEM encoded certificate/key',
}

try:
    with open(file_path, 'rb') as f:
        header = f.read(64)

    print(f"File: {file_path}")
    print(f"Size: {len(header)} bytes (header read)")
    print()

    # Show hex dump of header
    print("=== Header (first 64 bytes) ===")
    for i in range(0, min(len(header), 64), 16):
        hex_part = ' '.join(f'{b:02x}' for b in header[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header[i:i+16])
        print(f"{i:04x}  {hex_part:<48}  {ascii_part}")

    print("\n=== File Type Detection ===")

    # Check for matches
    matches = []
    for sig, desc in signatures.items():
        if header.startswith(sig):
            matches.append((len(sig), desc))
        elif sig in header[:20]:
            matches.append((len(sig), f"{desc} (found at offset {header.index(sig)})"))

    if matches:
        # Sort by signature length (longer = more specific)
        matches.sort(reverse=True, key=lambda x: x[0])
        for length, desc in matches:
            print(f"Match: {desc}")
    else:
        print("No known file signature detected")
        print("File may be: plaintext, encrypted, or unknown format")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
