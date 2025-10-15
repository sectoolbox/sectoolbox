# TITLE: ROT13 & Caesar Cipher
# DESCRIPTION: Decode ROT13 and try all Caesar cipher shifts
# CATEGORY: Decoding
# AUTHOR: Sectoolbox

file_path = '/uploads/sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    # Decode as text
    text = data.decode('utf-8', errors='ignore')

    print(f"File: {file_path}")
    print(f"Size: {len(data)} bytes")

    # ROT13 decode
    print("\n=== ROT13 Decode ===")
    rot13_text = ''
    for char in text:
        if 'a' <= char <= 'z':
            rot13_text += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            rot13_text += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            rot13_text += char

    print(rot13_text[:500])
    if len(rot13_text) > 500:
        print(f"... ({len(rot13_text)} total characters)")

    # Save ROT13 decoded
    with open('/uploads/rot13_decoded.txt', 'w') as out:
        out.write(rot13_text)
    print("\nSaved to: /uploads/rot13_decoded.txt")

    # Try all Caesar cipher shifts
    print("\n=== Caesar Cipher (All Shifts) ===")

    # Common English words for detection
    common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'her', 'was', 'one', 'our', 'out', 'flag', 'ctf']

    results = []

    for shift in range(26):
        shifted_text = ''
        for char in text:
            if 'a' <= char <= 'z':
                shifted_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                shifted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                shifted_text += char

        # Score based on common words
        lower_text = shifted_text.lower()
        score = sum(lower_text.count(' ' + word + ' ') for word in common_words)
        score += sum(lower_text.count(' ' + word) for word in common_words)

        # Also score based on character frequency
        if len(shifted_text) > 0:
            letter_freq = {}
            for char in shifted_text.lower():
                if 'a' <= char <= 'z':
                    letter_freq[char] = letter_freq.get(char, 0) + 1

            # Expected frequencies for English
            expected = {'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7}
            total_letters = sum(letter_freq.values())

            if total_letters > 0:
                freq_score = 0
                for letter, expected_pct in expected.items():
                    actual_pct = (letter_freq.get(letter, 0) / total_letters) * 100
                    freq_score += abs(expected_pct - actual_pct)

                # Lower is better, invert it
                score += max(0, 100 - freq_score)

        results.append({
            'shift': shift,
            'score': score,
            'text': shifted_text
        })

    # Sort by score
    results.sort(key=lambda x: x['score'], reverse=True)

    # Show top 5 results
    print("Top 5 most likely Caesar shifts:\n")

    for i, result in enumerate(results[:5], 1):
        shift = result['shift']
        print(f"Rank {i}: Shift {shift} (ROT{shift})")
        print(f"  Score: {result['score']:.1f}")
        print(f"  Preview: {result['text'][:150]}")
        print()

    # Save best result
    best = results[0]
    if best['shift'] != 0:
        with open('/uploads/caesar_decoded.txt', 'w') as out:
            out.write(best['text'])
        print(f"Best result (shift {best['shift']}) saved to: /uploads/caesar_decoded.txt")

    # Show all shifts in compact form
    print("\n=== All Caesar Shifts (First 80 chars) ===")
    for shift in range(26):
        shifted_text = ''
        for char in text[:80]:
            if 'a' <= char <= 'z':
                shifted_text += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                shifted_text += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                shifted_text += char

        print(f"ROT{shift:2d}: {shifted_text}")

except FileNotFoundError:
    print("Error: Please upload a file first!")
except Exception as e:
    print(f"Error: {e}")
