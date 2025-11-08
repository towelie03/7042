import matplotlib.pyplot as plt
import csv
from datetime import datetime
from tables import IP, FP, E, P, S_BOX, PC1, PC2, LEFT_SHIFTS

def hex_to_bitlist(hexstr, bits=64):
    v = int(hexstr, 16)
    b = bin(v)[2:].zfill(bits)
    return [int(x) for x in b]

def bitlist_to_hex(bits):
    s = ''.join(str(b) for b in bits)
    return hex(int(s, 2))[2:].upper().zfill(len(bits)//4)

def permute(bits, table):
    return [bits[i-1] for i in table]

def left_rotate(lst, n):
    return lst[n:] + lst[:n]

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

def sbox_substitution(bits48):
    out = []
    for i in range(8):
        block = bits48[i*6:(i+1)*6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOX[i][row][col]
        bin4 = bin(val)[2:].zfill(4)
        out.extend(int(x) for x in bin4)
    return out

def generate_subkeys(key_hex):
    if len(key_hex) != 16:
        raise ValueError("Key must be 16 hex characters (64 bits).")
    key_bits = hex_to_bitlist(key_hex, 64)
    key56 = permute(key_bits, PC1)
    C = key56[:28]
    D = key56[28:]
    subkeys = []
    for shift in LEFT_SHIFTS:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        CD = C + D
        subkey = permute(CD, PC2)
        subkeys.append(subkey)
    return subkeys

def feistel_function(R, subkey):
    expanded = permute(R, E)
    x = xor(expanded, subkey)
    sboxed = sbox_substitution(x)
    permuted = permute(sboxed, P)
    return permuted

def des_encrypt_roundwise(plaintext_hex, subkeys, rounds=16):
    bits = hex_to_bitlist(plaintext_hex, 64)
    bits = permute(bits, IP)
    L = bits[:32]
    R = bits[32:]
    round_outputs = []
    for i in range(rounds):
        f_out = feistel_function(R, subkeys[i])
        newR = xor(L, f_out)
        L, R = R, newR
        round_outputs.append(L + R)
    return round_outputs

def count_bit_diff(bits1, bits2):
    return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))

def save_to_csv(filename, diffs):
    with open(filename, mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Round", "Bit Differences"])
        for i, diff in enumerate(diffs, start=1):
            writer.writerow([i, diff])
    print(f"Saved data to {filename}")

def plot_and_save_graph(title, diffs, filename, color):
    plt.figure(figsize=(8, 5))
    plt.plot(range(1, 17), diffs, marker='o', color=color)
    plt.title(title)
    plt.xlabel("Round")
    plt.ylabel("Number of Differing Bits (out of 64)")
    plt.grid(True)
    plt.xticks(range(1, 17))
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()
    print(f"Saved graph to {filename}")

def spac_analysis(plaintext1, plaintext2, key):
    subkeys = generate_subkeys(key)
    rounds1 = des_encrypt_roundwise(plaintext1, subkeys)
    rounds2 = des_encrypt_roundwise(plaintext2, subkeys)
    diffs = [count_bit_diff(rounds1[i], rounds2[i]) for i in range(16)]

    print("\nSPAC Analysis")
    print("Round | Bit Differences")
    for i, diff in enumerate(diffs, start=1):
        print(f"{i:>5} | {diff}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_name = f"SPAC_results_{timestamp}.csv"
    png_name = f"SPAC_graph_{timestamp}.png"

    save_to_csv(csv_name, diffs)
    plot_and_save_graph("SPAC - Strict Plaintext Avalanche Criterion", diffs, png_name, 'tab:blue')

    return diffs

def skac_analysis(plaintext, key1, key2):
    subkeys1 = generate_subkeys(key1)
    subkeys2 = generate_subkeys(key2)
    rounds1 = des_encrypt_roundwise(plaintext, subkeys1)
    rounds2 = des_encrypt_roundwise(plaintext, subkeys2)
    diffs = [count_bit_diff(rounds1[i], rounds2[i]) for i in range(16)]

    print("\nSKAC Analysis")
    print("Round | Bit Differences")
    for i, diff in enumerate(diffs, start=1):
        print(f"{i:>5} | {diff}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_name = f"SKAC_results_{timestamp}.csv"
    png_name = f"SKAC_graph_{timestamp}.png"

    save_to_csv(csv_name, diffs)
    plot_and_save_graph("SKAC - Strict Key Avalanche Criterion", diffs, png_name, 'tab:red')

    return diffs

def main():
    pt = input("Enter plaintext (16 hex chars): ").strip()
    key = input("Enter key (16 hex chars): ").strip()

    print("\nSPAC")
    pt2 = input("Enter plaintext with 1-bit difference: ").strip()
    spac_analysis(pt, pt2, key)

    print("\nSKAC TEST")
    key2 = input("Enter key with 1-bit difference: ").strip()
    skac_analysis(pt, key, key2)


if __name__ == "__main__":
    main()

