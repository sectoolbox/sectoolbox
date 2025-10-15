# TITLE: 🔐 PE File Analyzer
# DESCRIPTION: Analyze Windows PE executables (basic analysis)
# CATEGORY: Malware Analysis
# AUTHOR: Sectoolbox

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
        print(f"File: {file_path}\n")

        # DOS Header
        e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
        print(f"PE Header Offset: 0x{e_lfanew:08x}")

        # PE Signature
        pe_sig = data[e_lfanew:e_lfanew+4]
        if pe_sig != b'PE\x00\x00':
            print("❌ Invalid PE signature")
        else:
            print("✅ Valid PE signature\n")

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
            print(f"\nArchitecture: {'64-bit (PE32+)' if is_64bit else '32-bit (PE32)'}")

            if is_64bit:
                entry_point = struct.unpack('<I', data[opt_offset+16:opt_offset+20])[0]
                image_base = struct.unpack('<Q', data[opt_offset+24:opt_offset+32])[0]
            else:
                entry_point = struct.unpack('<I', data[opt_offset+16:opt_offset+20])[0]
                image_base = struct.unpack('<I', data[opt_offset+28:opt_offset+32])[0]

            print(f"Entry Point: 0x{entry_point:08x}")
            print(f"Image Base: 0x{image_base:016x}")

            print("\n✅ Basic PE analysis complete")
            print("💡 Install 'pefile' for advanced analysis:")
            print("   await micropip.install('pefile')")

except FileNotFoundError:
    print("❌ Error: Please upload a file first!")
except Exception as e:
    print(f"❌ Error: {e}")
