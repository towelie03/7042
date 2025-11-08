# Task 2 – Extended Euclidean Algorithm Implementation

This program implements the **Extended Euclidean Algorithm** to compute the greatest common divisor (GCD) of two integers, while also finding integers `x` and `y` that satisfy the equation:

a * x + b * y = gcd(a, b)


---

## How The Program Works
- The function `gcd(a, b)`:
  - Prints each recursive step of the Euclidean algorithm.  
  - Computes integers `x` and `y` (Bezout coefficients) such that:

    ```
    a*x + b*y = gcd(a, b)
    ```

- The program prompts the user for:
  1. An integer `a` (the modulus).
  2. A non-negative integer `b` less than `a`.

- Test case: `a`=43 and `b`=17

---

## Test Case 

### Test Case 1 
- ***a:*** `43`
- ***b:*** `17`
- ***gcd(a,b)=c:*** `1`
- ***x:*** `2`
- ***y:***  `-5`
- ***a*x + b*y:*** `1`
- ***17mod43:*** `38`

### Test Case 2 
- ***a:*** `400`
- ***b:*** `10`
- ***gcd(a,b)=c:*** `10`
- ***x:*** `0`
- ***y:***  `1`
- ***a*x + b*y:*** `10`
- ***10mod400:*** `No modular inverse`


## How to Run

Run the program from the command line:

```bash
python task2.py

