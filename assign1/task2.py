def gcd(a, b):
    print(f"gcd({a},{b})")
    x0, x1 = 1, 0
    y0, y1 = 0, 1
    
    while b != 0:
        r = a % b
        q = a // b  
        
        x_next = x0 - q * x1
        y_next = y0 - q * y1
        
        a, b = b, r
        x0, x1 = x1, x_next
        y0, y1 = y1, y_next
        
        print(f"gcd({a},{b})")
    
    return a, x0, y0

def main():
    a = int(input("Input an integer a, which is the modulus: "))
    b = int(input("Input a non-negative integer b that is less than a: "))
    gcd_val, x, y = gcd(a, b)

    print(f"gcd({a}, {b}) = {gcd_val}")
    print(f"x = {x}")
    print(f"y = {y}")
    print(f"{a}*{x} + {b}*{y} = {gcd_val}")

    if gcd_val == 1:
        mod_inv = y % a
        print(f"Modular multiplicative inverse of {b} mod {a} is {mod_inv}")
    else:
        print(f"No modular inverse exists because gcd({a},{b}) = {gcd_val}")

if __name__ == "__main__":
    main()
