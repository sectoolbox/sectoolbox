// Python Forensics Example Scripts

export interface PythonExample {
  id: string
  title: string
  description: string
  category: string
  code: string
  requiredPackages?: string[]
}

export const pythonExamples: PythonExample[] = [
  {
    id: 'file-hash',
    title: '🔍 File Hash Calculator',
    description: 'Calculate MD5, SHA1, SHA256 hashes of uploaded files',
    category: 'File Analysis',
    code: `import hashlib

# Upload your file first
file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print("=== File Hash Calculator ===")
    print(f"File: {file_path}")
    print(f"Size: {len(data):,} bytes ({len(data)/1024:.2f} KB)\\n")

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
`
  },
  {
    id: 'entropy-analysis',
    title: '🧬 File Entropy Analyzer',
    description: 'Calculate entropy to detect encryption/packing',
    category: 'File Analysis',
    code: `import math
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
    print(f"Size: {len(data):,} bytes\\n")

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
    print(f"\\n=== Block Analysis (4KB blocks) ===")
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
`
  },
  {
    id: 'string-extractor',
    title: '🔎 String Extractor',
    description: 'Extract printable strings from binary files',
    category: 'File Analysis',
    code: `import re

def extract_strings(data, min_length=4):
    """Extract printable ASCII strings"""
    # ASCII strings
    ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
    ascii_strings = re.findall(ascii_pattern, data)

    # Unicode strings (UTF-16 LE)
    unicode_pattern = rb'(?:[ -~]\\x00){' + str(min_length).encode() + rb',}'
    unicode_strings = re.findall(unicode_pattern, data)

    return ascii_strings, unicode_strings

# Upload your file first
file_path = '/uploads/sample.bin'
min_length = 6

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"=== String Extractor (min length: {min_length}) ===")
    print(f"File: {file_path}\\n")

    ascii_strings, unicode_strings = extract_strings(data, min_length)

    # Display ASCII strings
    print(f"📝 ASCII Strings Found: {len(ascii_strings)}")
    print("-" * 50)
    for i, s in enumerate(ascii_strings[:50]):  # First 50
        try:
            decoded = s.decode('ascii', errors='ignore')
            print(f"{i+1:3}. {decoded}")
        except:
            pass

    if len(ascii_strings) > 50:
        print(f"\\n... and {len(ascii_strings) - 50} more")

    # Display Unicode strings (sample)
    if unicode_strings:
        print(f"\\n🔤 Unicode Strings Found: {len(unicode_strings)}")
        print("-" * 50)
        for i, s in enumerate(unicode_strings[:20]):  # First 20
            try:
                decoded = s.decode('utf-16le', errors='ignore')
                print(f"{i+1:3}. {decoded}")
            except:
                pass

    # Find interesting patterns
    print("\\n🔍 Interesting Patterns:")
    text = data.decode('ascii', errors='ignore')

    urls = re.findall(r'https?://[^\\s<>"{}|\\\\^\\[\\]\']+', text)
    emails = re.findall(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', text)
    ips = re.findall(r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b', text)

    if urls:
        print(f"  🌐 URLs: {len(urls)}")
        for url in urls[:5]:
            print(f"     {url}")

    if emails:
        print(f"  📧 Emails: {len(emails)}")
        for email in emails[:5]:
            print(f"     {email}")

    if ips:
        print(f"  🖧  IPs: {len(set(ips))}")
        for ip in list(set(ips))[:5]:
            print(f"     {ip}")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
`
  },
  {
    id: 'pe-analyzer',
    title: '🔐 PE File Analyzer',
    description: 'Analyze Windows PE executables (requires pefile)',
    category: 'Malware Analysis',
    requiredPackages: ['pefile'],
    code: `# Note: This requires 'pefile' package
# Run: await micropip.install('pefile') first

import struct
from datetime import datetime

file_path = '/uploads/sample.exe'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Check DOS header
    if data[:2] != b'MZ':
        print("❌ Not a valid PE file (missing MZ signature)")
    else:
        print("=== PE File Analysis ===")
        print(f"File: {file_path}\\n")

        # DOS Header
        e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
        print(f"PE Header Offset: 0x{e_lfanew:08x}")

        # PE Signature
        pe_sig = data[e_lfanew:e_lfanew+4]
        if pe_sig != b'PE\\x00\\x00':
            print("❌ Invalid PE signature")
        else:
            print("✅ Valid PE signature\\n")

            # COFF Header
            coff_offset = e_lfanew + 4
            machine = struct.unpack('<H', data[coff_offset:coff_offset+2])[0]
            num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
            timestamp = struct.unpack('<I', data[coff_offset+4:coff_offset+8])[0]

            machine_types = {
                0x014c: 'x86 (32-bit)',
                0x8664: 'x64 (64-bit)',
                0x01c0: 'ARM',
                0xaa64: 'ARM64'
            }

            print("=== COFF Header ===")
            print(f"Machine: {machine_types.get(machine, f'Unknown (0x{machine:04x})')}")
            print(f"Sections: {num_sections}")

            if timestamp > 0:
                compile_time = datetime.fromtimestamp(timestamp)
                print(f"Compile Time: {compile_time}")

            # Optional Header
            opt_offset = coff_offset + 20
            magic = struct.unpack('<H', data[opt_offset:opt_offset+2])[0]

            is_64bit = (magic == 0x20b)
            print(f"\\nArchitecture: {'64-bit (PE32+)' if is_64bit else '32-bit (PE32)'}")

            if is_64bit:
                entry_point = struct.unpack('<I', data[opt_offset+16:opt_offset+20])[0]
                image_base = struct.unpack('<Q', data[opt_offset+24:opt_offset+32])[0]
            else:
                entry_point = struct.unpack('<I', data[opt_offset+16:opt_offset+20])[0]
                image_base = struct.unpack('<I', data[opt_offset+28:opt_offset+32])[0]

            print(f"Entry Point: 0x{entry_point:08x}")
            print(f"Image Base: 0x{image_base:016x}")

            print("\\n✅ Basic PE analysis complete")
            print("💡 Install 'pefile' for advanced analysis:")
            print("   await micropip.install('pefile')")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
`
  },
  {
    id: 'base64-decoder',
    title: '🔓 Base64 Decoder',
    description: 'Find and decode Base64 strings in files',
    category: 'Decoding',
    code: `import base64
import re

file_path = '/uploads/sample.txt'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Convert to text
    text = data.decode('utf-8', errors='ignore')

    print("=== Base64 Decoder ===")
    print(f"File: {file_path}\\n")

    # Find potential Base64 strings (at least 20 chars)
    b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
    matches = re.findall(b64_pattern, text)

    print(f"Found {len(matches)} potential Base64 strings\\n")

    decoded_count = 0
    for i, match in enumerate(matches[:20], 1):  # Decode first 20
        try:
            # Attempt to decode
            decoded = base64.b64decode(match)

            # Check if decoded data is printable
            if all(32 <= b < 127 or b in [9, 10, 13] for b in decoded[:100]):
                decoded_text = decoded.decode('utf-8', errors='ignore')
                print(f"{i}. Original ({len(match)} chars):")
                print(f"   {match[:60]}{'...' if len(match) > 60 else ''}")
                print(f"   Decoded:")
                print(f"   {decoded_text[:100]}{'...' if len(decoded_text) > 100 else ''}")
                print()
                decoded_count += 1

        except Exception:
            continue

    if decoded_count == 0:
        print("⚠️  No valid Base64-encoded text found")
    else:
        print(f"✅ Successfully decoded {decoded_count} strings")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
`
  },
  {
    id: 'hex-dump',
    title: '📄 Hex Dump Viewer',
    description: 'Display file contents in hexadecimal format',
    category: 'File Analysis',
    code: `def hex_dump(data, offset=0, length=256):
    """Generate hex dump similar to xxd"""
    lines = []
    for i in range(0, min(len(data), length), 16):
        # Offset
        line = f"{offset + i:08x}  "

        # Hex bytes
        hex_part = ""
        ascii_part = ""
        for j in range(16):
            if i + j < len(data):
                byte = data[i + j]
                hex_part += f"{byte:02x} "
                ascii_part += chr(byte) if 32 <= byte < 127 else "."
            else:
                hex_part += "   "
                ascii_part += " "

            # Add extra space in middle
            if j == 7:
                hex_part += " "

        line += hex_part + " |" + ascii_part + "|"
        lines.append(line)

    return "\\n".join(lines)

# Upload your file first
file_path = '/uploads/sample.bin'
display_bytes = 512  # Show first 512 bytes

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print("=== Hex Dump Viewer ===")
    print(f"File: {file_path}")
    print(f"Size: {len(data):,} bytes")
    print(f"Showing: first {min(display_bytes, len(data))} bytes\\n")

    print(hex_dump(data, length=display_bytes))

    if len(data) > display_bytes:
        print(f"\\n... and {len(data) - display_bytes:,} more bytes")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
`
  },
  {
    id: 'zip-analyzer',
    title: '📦 ZIP Archive Analyzer',
    description: 'Analyze ZIP file structure and contents',
    category: 'Archive Analysis',
    code: `import zipfile
from datetime import datetime

file_path = '/uploads/sample.zip'

try:
    with zipfile.ZipFile(file_path, 'r') as zf:
        print("=== ZIP Archive Analysis ===")
        print(f"File: {file_path}\\n")

        # Get file list
        file_list = zf.namelist()
        print(f"Total Files: {len(file_list)}")

        # Calculate total size
        total_compressed = 0
        total_uncompressed = 0

        print("\\n=== File List ===")
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
        print("\\n=== Security Analysis ===")
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
        print("\\n=== Content Preview ===")
        for info in zf.infolist()[:5]:
            if info.file_size < 1024 and info.file_size > 0:
                try:
                    content = zf.read(info.filename)
                    text = content.decode('utf-8', errors='ignore')
                    if text.isprintable() or all(c in text for c in '\\n\\r\\t'):
                        print(f"\\n📄 {info.filename}:")
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
`
  },
  {
    id: 'json-beautifier',
    title: '✨ JSON Beautifier',
    description: 'Parse and prettify JSON data',
    category: 'Data Processing',
    code: `import json

file_path = '/uploads/data.json'

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print("=== JSON Beautifier ===")
    print(f"File: {file_path}\\n")

    # Pretty print with indentation
    pretty_json = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)

    print(pretty_json)

    # Statistics
    print("\\n=== Statistics ===")

    def count_structure(obj, depth=0):
        stats = {'objects': 0, 'arrays': 0, 'strings': 0, 'numbers': 0, 'booleans': 0, 'nulls': 0, 'max_depth': depth}

        if isinstance(obj, dict):
            stats['objects'] += 1
            for value in obj.values():
                sub_stats = count_structure(value, depth + 1)
                for key in sub_stats:
                    if key == 'max_depth':
                        stats['max_depth'] = max(stats['max_depth'], sub_stats['max_depth'])
                    else:
                        stats[key] += sub_stats[key]
        elif isinstance(obj, list):
            stats['arrays'] += 1
            for item in obj:
                sub_stats = count_structure(item, depth + 1)
                for key in sub_stats:
                    if key == 'max_depth':
                        stats['max_depth'] = max(stats['max_depth'], sub_stats['max_depth'])
                    else:
                        stats[key] += sub_stats[key]
        elif isinstance(obj, str):
            stats['strings'] += 1
        elif isinstance(obj, (int, float)):
            stats['numbers'] += 1
        elif isinstance(obj, bool):
            stats['booleans'] += 1
        elif obj is None:
            stats['nulls'] += 1

        return stats

    stats = count_structure(data)
    print(f"Objects:  {stats['objects']}")
    print(f"Arrays:   {stats['arrays']}")
    print(f"Strings:  {stats['strings']}")
    print(f"Numbers:  {stats['numbers']}")
    print(f"Booleans: {stats['booleans']}")
    print(f"Nulls:    {stats['nulls']}")
    print(f"Max Nesting Depth: {stats['max_depth']}")

except json.JSONDecodeError as e:
    print(f"❌ JSON Parse Error: {e}")
except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
`
  },
  {
    id: 'file-signature',
    title: '🔖 File Signature Detector',
    description: 'Identify file type by magic bytes',
    category: 'File Analysis',
    code: `def identify_file_type(data):
    """Identify file type by magic bytes (file signature)"""

    # Common file signatures
    signatures = [
        (b'\\x50\\x4B\\x03\\x04', 'ZIP Archive'),
        (b'\\x50\\x4B\\x05\\x06', 'ZIP Archive (empty)'),
        (b'\\x50\\x4B\\x07\\x08', 'ZIP Archive (spanned)'),
        (b'\\x4D\\x5A', 'PE Executable (EXE/DLL)'),
        (b'\\x7F\\x45\\x4C\\x46', 'ELF Executable'),
        (b'\\xFF\\xD8\\xFF', 'JPEG Image'),
        (b'\\x89\\x50\\x4E\\x47\\x0D\\x0A\\x1A\\x0A', 'PNG Image'),
        (b'GIF87a', 'GIF Image (87a)'),
        (b'GIF89a', 'GIF Image (89a)'),
        (b'\\x42\\x4D', 'BMP Image'),
        (b'\\x49\\x49\\x2A\\x00', 'TIFF Image (little-endian)'),
        (b'\\x4D\\x4D\\x00\\x2A', 'TIFF Image (big-endian)'),
        (b'%PDF-', 'PDF Document'),
        (b'\\x25\\x21\\x50\\x53', 'PostScript'),
        (b'\\xD0\\xCF\\x11\\xE0\\xA1\\xB1\\x1A\\xE1', 'MS Office Document (DOC/XLS/PPT)'),
        (b'PK\\x03\\x04\\x14\\x00\\x06\\x00', 'MS Office (OOXML)'),
        (b'Rar!\\x1A\\x07', 'RAR Archive (v4)'),
        (b'Rar!\\x1A\\x07\\x01\\x00', 'RAR Archive (v5)'),
        (b'\\x37\\x7A\\xBC\\xAF\\x27\\x1C', '7-Zip Archive'),
        (b'\\x1F\\x8B\\x08', 'GZIP Archive'),
        (b'BZh', 'BZIP2 Archive'),
        (b'\\xFD\\x37\\x7A\\x58\\x5A\\x00', 'XZ Archive'),
        (b'\\x52\\x61\\x72\\x21', 'RAR Archive'),
        (b'\\x75\\x73\\x74\\x61\\x72', 'TAR Archive'),
        (b'\\x4F\\x67\\x67\\x53', 'OGG Media'),
        (b'ID3', 'MP3 Audio'),
        (b'\\xFF\\xFB', 'MP3 Audio (no ID3)'),
        (b'fLaC', 'FLAC Audio'),
        (b'RIFF', 'RIFF Container (WAV/AVI)'),
        (b'\\x00\\x00\\x00\\x14\\x66\\x74\\x79\\x70', 'MP4 Video'),
        (b'\\x00\\x00\\x00\\x18\\x66\\x74\\x79\\x70', 'MP4 Video'),
        (b'\\x1A\\x45\\xDF\\xA3', 'Matroska/WebM Video'),
        (b'FLV', 'Flash Video'),
        (b'\\x30\\x26\\xB2\\x75\\x8E\\x66\\xCF\\x11', 'WMA/WMV'),
        (b'SQLite format 3', 'SQLite Database'),
        (b'\\x4C\\x00\\x00\\x00', 'Windows Shortcut (LNK)'),
        (b'\\xCA\\xFE\\xBA\\xBE', 'Java Class File'),
        (b'\\x4D\\x45\\x54\\x41\\x2D\\x49\\x4E\\x46', 'Java JAR'),
        (b'\\xED\\xAB\\xEE\\xDB', 'RPM Package'),
        (b'!<arch>', 'Debian Package'),
        (b'\\x1F\\x9D', 'Compress (.Z)'),
        (b'\\x1F\\xA0', 'Compress (.Z)'),
        (b'BM', 'BMP Image'),
        (b'\\x00\\x00\\x01\\x00', 'ICO Image'),
        (b'\\x00\\x00\\x02\\x00', 'CUR Cursor'),
        (b'\\x52\\x49\\x46\\x46', 'RIFF (WAV/AVI/WebP)'),
    ]

    # Check signatures
    matches = []
    for sig, desc in signatures:
        if data.startswith(sig):
            matches.append(desc)

    # Check for text files
    try:
        text = data[:1024].decode('utf-8')
        if text.isprintable() or all(c in text for c in '\\n\\r\\t'):
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
    print(f"Size: {len(data):,} bytes\\n")

    # Display first 64 bytes as hex
    print("First 64 bytes (hex):")
    hex_dump = ' '.join(f'{b:02x}' for b in data[:64])
    for i in range(0, len(hex_dump), 48):
        print(f"  {hex_dump[i:i+48]}")

    print("\\nFirst 64 bytes (ASCII):")
    ascii_dump = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[:64])
    for i in range(0, len(ascii_dump), 64):
        print(f"  {ascii_dump[i:i+64]}")

    # Identify file type
    print("\\n=== File Type Detection ===")
    file_types = identify_file_type(data)

    for ft in file_types:
        print(f"✓ {ft}")

    # Additional analysis
    print("\\n=== Additional Info ===")
    print(f"Null bytes: {data.count(b'\\x00'):,} ({data.count(b'\\x00')/len(data)*100:.1f}%)")

    # Check if mostly ASCII
    ascii_count = sum(1 for b in data[:10000] if 32 <= b < 127 or b in [9, 10, 13])
    print(f"ASCII characters: {ascii_count/min(len(data), 10000)*100:.1f}%")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
`
  }
]

export const exampleCategories = [
  'All',
  'File Analysis',
  'Malware Analysis',
  'Decoding',
  'Archive Analysis',
  'Data Processing'
]
