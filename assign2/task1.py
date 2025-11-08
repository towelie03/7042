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

def des_encrypt_block(plaintext_hex, subkeys, rounds=16):
    if len(plaintext_hex) != 16:
        raise ValueError("Plaintext must be 16 hex chars (64 bits).")
    bits = hex_to_bitlist(plaintext_hex, 64)
    bits = permute(bits, IP)
    L = bits[:32]
    R = bits[32:]
    for i in range(rounds):
        f_out = feistel_function(R, subkeys[i])
        newR = xor(L, f_out)
        L, R = R, newR
    preoutput = R + L
    cipher_bits = permute(preoutput, FP)
    return bitlist_to_hex(cipher_bits)

def des_decrypt_block(ciphertext_hex, subkeys):
    if len(ciphertext_hex) != 16:
        raise ValueError("Ciphertext must be 16 hex chars (64 bits).")
    bits = hex_to_bitlist(ciphertext_hex, 64)
    bits = permute(bits, IP)
    L = bits[:32]
    R = bits[32:]
    for i in range(15, -1, -1):
        f_out = feistel_function(R, subkeys[i])
        newR = xor(L, f_out)
        L = R
        R = newR
    preoutput = R + L
    plain_bits = permute(preoutput, FP)
    return bitlist_to_hex(plain_bits)

def main():
    pt = input("Enter the plaintext: ")
    key = input("Enter key: ")
    
    subkeys = generate_subkeys(key)
    cipher = des_encrypt_block(pt, subkeys)
    decrypted = des_decrypt_block(cipher, subkeys)

    print("\nPlaintext:", pt)
    print("Key:", key)
    print("\nEncrypted:", cipher)
    print("Decrypted:", decrypted)


if __name__ == "__main__":
  main() 
