from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import os

print("Generating 2048-bit RSA key pair for Bob (Receiver)...")
bob_key = RSA.generate(2048, e=65537)   # 2048-bit key, fixed e=65537

bob_public_key = bob_key.publickey()
bob_private_key = bob_key

print(f"n (modulus) has {bob_key.n.bit_length()} bits")
print(f"Public exponent e = {bob_key.e}\n")

print("Alice generates a 256-bit AES key and encrypts it for Bob...")

aes_key = get_random_bytes(32)  
print(f"Original AES Key (hex): {aes_key.hex()}")

encryptor = PKCS1_OAEP.new(bob_public_key)
encrypted_aes_key = encryptor.encrypt(aes_key)

print(f"Encrypted AES Key (hex): {encrypted_aes_key.hex()[:120]}... ({len(encrypted_aes_key)} bytes total)\n")

print("Bob's private key uses CRT optimization with these parameters:")
print(f"  p = {bob_private_key.p}")
print(f"  q = {bob_private_key.q}")
print(f"  dP = d mod (p-1) = {bob_private_key.invq}")  
print(f"  dQ = d mod (q-1) = {bob_private_key.invp}")  
print(f"  qInv = q^{-1} mod p = {bob_private_key.invq}\n")

decryptor = PKCS1_OAEP.new(bob_private_key)  
decrypted_aes_key = decryptor.decrypt(encrypted_aes_key)

print(f"Decrypted AES Key (hex): {decrypted_aes_key.hex()}")

if decrypted_aes_key == aes_key:
    print("\nAES key successfully exchanged using secure RSA")
    print("Bob can use this shared AES key for symmetric encryption.")
else:
    print("\nKey mismatch!")

import time

ciphertext_int = int.from_bytes(encrypted_aes_key, 'big')

start = time.time()
for _ in range(100):
    _ = pow(ciphertext_int, bob_private_key.d, bob_private_key.n)  # Standard (slow)
end = time.time()
print(f"\nStandard RSA decryption: {(end-start)*1000:.2f} ms")

start = time.time()
for _ in range(100):
    _ = PKCS1_OAEP.new(bob_private_key).decrypt(encrypted_aes_key)  # Uses CRT
end = time.time()
print(f"CRT optimized RSA decryption: {(end-start)*1000:.2f} ms")
