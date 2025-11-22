import os
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from task2 import Task2
from PIL import Image
import io


def generate_rsa_keypair():
    key = RSA.generate(2048, e=65537)
    return key, key.publickey()


def rsa_encrypt_aes_key(bob_public_key, aes_key):
    cipher = PKCS1_OAEP.new(bob_public_key)
    return cipher.encrypt(aes_key)


def rsa_decrypt_aes_key(bob_private_key, encrypted_key):
    cipher = PKCS1_OAEP.new(bob_private_key)
    return cipher.decrypt(encrypted_key)


def encrypt_image_file(image_path, aes_key):
    with open(image_path, "rb") as f:
        plaintext = f.read()

    iv = os.urandom(16)

    ciphertext = Task2.aes_cbc_encrypt(plaintext, aes_key, iv)

    encrypted_path = "encrypted_image.bin"
    with open(encrypted_path, "wb") as f:
        f.write(iv + ciphertext)

    return encrypted_path, iv, len(plaintext)


def decrypt_image_file(encrypted_path, aes_key):
    with open(encrypted_path, "rb") as f:
        data = f.read()

    iv = data[:16]
    ciphertext = data[16:]

    decrypted_bytes = Task2.aes_cbc_decrypt(ciphertext, aes_key, iv)

    decrypted_path = "decrypted_image.png"
    with open(decrypted_path, "wb") as f:
        f.write(decrypted_bytes)

    return decrypted_path, decrypted_bytes


def main():
    image_path = "./banana_fish.png"
    print("TASK 4: Image Encryption Using AES-256 CBC (BBS Key)\n")

    if not os.path.exists(image_path):
        print(f"ERROR: Image not found at path: {image_path}")
        return

    bob_private_key, bob_public_key = generate_rsa_keypair()
    print(f"Bob generated 2048-bit RSA key (modulus = {bob_private_key.n.bit_length()} bits)\n")

    print("Alice generating 256-bit AES key using Blum-Blum-Shub PRNG...")
    aes_key = Task2.generate_aes_key_bbs()
    print(f"AES Key: {aes_key.hex()}\n")

    print("Alice encrypting AES key with Bob’s RSA public key (OAEP)...")
    encrypted_key = rsa_encrypt_aes_key(bob_public_key, aes_key)

    received_key = rsa_decrypt_aes_key(bob_private_key, encrypted_key)
    print(f"Bob recovered key: {'SUCCESS' if received_key == aes_key else 'FAILED'}\n")

    print(f"Alice encrypting image: {image_path}")
    encrypted_file, iv, size = encrypt_image_file(image_path, received_key)
    print(f"Encrypted image saved as: {encrypted_file} ({size:,} bytes)\n")

    print(f"Bob decrypting {encrypted_file}...")
    decrypted_file, decrypted_bytes = decrypt_image_file(encrypted_file, received_key)
    print(f"Decrypted image saved as: {decrypted_file}\n")

    with open(image_path, "rb") as f:
        original_data = f.read()

    original_hash = hashlib.sha256(original_data).hexdigest()
    decrypted_hash = hashlib.sha256(decrypted_bytes).hexdigest()

    print("Image Integrity Check:")
    print(f"Original SHA-256 : {original_hash}")
    print(f"Decrypted SHA-256: {decrypted_hash}")

    if decrypted_hash == original_hash:
        print("\nImage decrypted successfully and matches the original")
    else:
        print("\nDecrypted image does NOT match the original")

    try:
        img = Image.open(io.BytesIO(decrypted_bytes))
        img.show()
        print("\n(Displayed decrypted image successfully.)")
    except Exception as e:
        print(f"\nCould not display image: {e}")


if __name__ == "__main__":
    main()

