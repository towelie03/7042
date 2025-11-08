def create_matrix(keyword):
    #make a 5x5 matrix
    key = keyword.upper().replace(" ", "").replace("J", "I")  
    
    check = set()
    unique_key = []
    for char in key:
        if char not in check:
            unique_key.append(char)
            check.add(char)

    letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  

    matrix_chars = unique_key
    for char in letters:
        if char not in check:
            matrix_chars.append(char)
            check.add(char)

    playfair_matrix = []
    for i in range(0, 25, 5): 
        playfair_matrix.append(matrix_chars[i:i+5])
    
    return playfair_matrix

def display_playfair(matrix):
    print("Playfair 5x5 Matrix:")
    print("+" + "-" * 11 + "+")
    for row in matrix:
        print("| " + " ".join(row) + " |")
    print("+" + "-" * 11 + "+")

def search_pos_of_char(matrix, char):
    for i, row in enumerate(matrix):
        if char in row:
            return i, row.index(char)
    return None

def format_text(plaintext):
    text = ''.join(c.upper() for c in plaintext if c.isalpha()).replace('J', 'I')
    result = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                result.append(a + 'X')
                i += 1
            else:
                result.append(a + b)
                i += 2
        else:
            result.append(a + 'X')
            i += 1
    return result

def encrypt_digraph(matrix, digraph):
    (r1, c1) = search_pos_of_char(matrix, digraph[0])
    (r2, c2) = search_pos_of_char(matrix, digraph[1])
    
    if r1 == r2:  
        return matrix[r1][(c1+1)%5] + matrix[r2][(c2+1)%5]
    elif c1 == c2:
        return matrix[(r1+1)%5][c1] + matrix[(r2+1)%5][c2]
    else:  
        return matrix[r1][c2] + matrix[r2][c1]

def encrypt_text(matrix, plaintext):
    digraphs = format_text(plaintext)
    ciphertext = ''.join(encrypt_digraph(matrix, dg) for dg in digraphs)
    return ciphertext

def main():
    keyword = input("Enter keyword: ").strip()
    if not keyword:
        print("Error: No keyword entered!")
        return
    
    plaintext = input("Enter plaintext: ").strip()
    if not plaintext:
        print("Error: No plaintext entered!")
        return
    
    pf_matrix = create_matrix(keyword)
    display_playfair(pf_matrix)

    ciphertext = encrypt_text(pf_matrix, plaintext)
    print(f"\nPlaintext : {plaintext}")
    print(f"Ciphertext: {ciphertext}")

if __name__ == "__main__":
    main()

