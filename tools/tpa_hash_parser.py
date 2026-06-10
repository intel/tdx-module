import sys

HEX_BASE = 16
BITS_PER_QWORD = 16

def print_qword_at_index(tpa_hash, qword_idx):
    # Assumption, the tpa_hash is in HEX
    # Remove the "0x" prefix if present
    if tpa_hash.startswith('0x'):
        tpa_hash = tpa_hash[2:]

    # Split the hex string into 6 qwords
    qwords_arr = [tpa_hash[i : i + BITS_PER_QWORD] for i in range(0, len(tpa_hash), BITS_PER_QWORD)]

    if qword_idx + 1 > len(qwords_arr):
        # Empty Q word
        print("0x0")
    else:
        # The TPA itself reads the hash in reverse little endian order
        # Reverse the requested qword
        modified_qword = list(qwords_arr[qword_idx][::-1])

        # Set the requested qword to little endian formatting
        for i in range(0, len(modified_qword) - 1, 2):
            modified_qword[i], modified_qword[i + 1] = modified_qword[i + 1], modified_qword[i]

        print("0x%s" % ''.join(modified_qword))

if __name__ == '__main__':
    # idx 1 contains the desired Q word
    # idx 2 contains the TPA hash
    if len(sys.argv) != 3:
        sys.exit(1)

    qword_arg = sys.argv[1]
    tpa_hash = sys.argv[2]

    qword_map = {"Q0": 0, "Q1": 1, "Q2": 2, "Q3": 3, "Q4": 4, "Q5": 5}

    if qword_arg in qword_map:
        print_qword_at_index(tpa_hash, qword_map[qword_arg])
    else:
        print("Invalid Qword Index. Please use Q0 to Q5.")
        sys.exit(1)
