# TITLE: File Carver
# DESCRIPTION: Carve and extract embedded files from binary data
# CATEGORY: Forensics
# AUTHOR: Sectoolbox

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")
    print("\n=== File Carving Results ===")

    # File signatures with start and end markers
    file_types = [
        {
            'name': 'JPEG',
            'start': b'\xff\xd8\xff',
            'end': b'\xff\xd9',
            'ext': 'jpg'
        },
        {
            'name': 'PNG',
            'start': b'\x89PNG\r\n\x1a\n',
            'end': b'IEND\xae\x42\x60\x82',
            'ext': 'png'
        },
        {
            'name': 'GIF',
            'start': b'GIF89a',
            'end': b'\x00\x3b',
            'ext': 'gif'
        },
        {
            'name': 'PDF',
            'start': b'%PDF',
            'end': b'%%EOF',
            'ext': 'pdf'
        },
        {
            'name': 'ZIP',
            'start': b'PK\x03\x04',
            'end': b'PK\x05\x06',
            'ext': 'zip'
        }
    ]

    carved_files = []

    for ftype in file_types:
        pos = 0
        instance = 1

        while True:
            # Find start marker
            start_pos = data.find(ftype['start'], pos)
            if start_pos == -1:
                break

            # Find end marker
            end_pos = data.find(ftype['end'], start_pos + len(ftype['start']))
            if end_pos == -1:
                # No end marker found, skip
                pos = start_pos + 1
                continue

            # Include end marker in carved data
            end_pos += len(ftype['end'])

            # Extract carved file
            carved_data = data[start_pos:end_pos]

            # Save to virtual filesystem
            output_filename = f"/uploads/carved_{ftype['ext']}_{instance}.{ftype['ext']}"

            try:
                with open(output_filename, 'wb') as out:
                    out.write(carved_data)

                carved_files.append({
                    'type': ftype['name'],
                    'filename': output_filename,
                    'offset': start_pos,
                    'size': len(carved_data)
                })

                print(f"[+] Carved {ftype['name']} file:")
                print(f"    Filename: {output_filename}")
                print(f"    Offset: {start_pos} - {end_pos}")
                print(f"    Size: {len(carved_data)} bytes")
                print()

                instance += 1
            except Exception as e:
                print(f"[!] Failed to save carved file: {e}")

            pos = end_pos

    # Summary
    print("=== Summary ===")
    if carved_files:
        print(f"Total files carved: {len(carved_files)}")
        print("\nCarved files by type:")
        from collections import Counter
        type_counts = Counter(f['type'] for f in carved_files)
        for ftype, count in type_counts.items():
            print(f"  {ftype}: {count}")

        print("\nAll carved files are saved in /uploads/ directory")
        print("Use the file browser to download them")
    else:
        print("No files could be carved from the input")
        print("\nTip: This tool looks for complete file signatures")
        print("If no files were found, try:")
        print("  - Using hex dump to manually inspect the data")
        print("  - Checking for corrupted or partial files")
        print("  - Using steganography detector for hidden data")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
