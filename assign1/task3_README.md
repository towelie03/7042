# Playfair Cipher Implementation

This program implements the **Playfair cipher**, a digraph substitution cipher that encrypts text using a 5x5 matrix generated from a keyword.  

The Playfair cipher provides more security than simple monoalphabetic ciphers (like Caesar) by encrypting **pairs of letters** instead of single characters.

---

## How The Program Works

1. **Keyword Matrix Construction**
   - Remove duplicate letters from the keyword.
   - Convert letters to uppercase and replace `J` with `I`.
   - Fill a 5x5 matrix with the keyword letters first, then the remaining letters of the alphabet (`A-Z`, excluding `J`).

2. **Plaintext Formatting**
   - Convert text to uppercase, ignoring punctuation and spaces.
   - Replace `J` with `I`.
   - Split the text into **digraphs (pairs)**:
     - If both letters are the same (e.g., `LL`), insert an `X` between them.
     - If the text length is odd, append an `X`.

3. **Encryption Rules**
   - For each digraph:
     - **Same Row** → Replace each letter with the letter to its right (wrap around if needed).  
     - **Same Column** → Replace each letter with the letter below it (wrap around if needed).  
     - **Rectangle Rule** → Replace each letter with the letter in the same row but in the column of the other letter.

4. **Ciphertext**  
   - Concatenate all encrypted digraphs into the final ciphertext.

---

## Test Cases

### Test Case 1
- **Keyword:** `MONARCHY`  
- **Plaintext:** `test`  
- **Ciphertext:** `LKTL`

---

### Test Case 2
- **Keyword:** `BALLOON`  
- **Plaintext:** `banana`  
- **Ciphertext:** `ALBLBL`

---

### Test Case 3
- **Keyword:** `TEST THREE`  
- **Plaintext:** `playfair cipher`  
- **Ciphertext:** `QKDVABMEBKQSST`

---

## How to Run

Run the program:

```bash
python playfair.py

