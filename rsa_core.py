import random
import math

# ==== RSA Core Functions ====

def gcd(a, b):
    """Greatest Common Divisor"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(e, phi):
    """Modular Multiplicative Inverse"""
    gcd_val, x, y = extended_gcd(e, phi)
    if gcd_val != 1:
        raise Exception("Modular inverse tidak ada")
    return (x % phi + phi) % phi

def is_prime_miller_rabin(n, k=10):
    """Miller-Rabin Primality Test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Test k kali
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_prime(bits=16):
    """Generate prime number dengan ukuran bits tertentu"""
    while True:
        num = random.randrange(2**(bits-1), 2**bits)
        if num % 2 == 0:
            num += 1
        if is_prime_miller_rabin(num):
            return num

def generate_keypair(bits=16):
    """
    Generate RSA key pair
    bits: ukuran bit untuk p dan q
    Returns: (public_key, private_key)
    """
    print(f"[RSA] Generating {bits}-bit primes...")
    
    # 1. Generate dua prime number p dan q
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:  # pastikan p != q
        q = generate_prime(bits)
    
    # 2. Hitung n = p * q
    n = p * q
    
    # 3. Hitung phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    
    # 4. Pilih e dimana 1 < e < phi dan gcd(e, phi) = 1
    # e = 65537 
    if e >= phi or gcd(e, phi) != 1:
        # Cari e yang valid
        e = random.randrange(2, phi)
        while gcd(e, phi) != 1:
            e = random.randrange(2, phi)
    
    # 5. Hitung d = e^-1 mod phi
    d = mod_inverse(e, phi)
    
    print(f"[RSA] Key generated: p={p}, q={q}, n={n}, e={e}, d={d}")
    
    # Public key: (e, n), Private key: (d, n)
    return ((e, n), (d, n))

def encrypt_rsa(plaintext, public_key):
    """
    Encrypt menggunakan RSA
    plaintext: integer atau string
    public_key: (e, n)
    """
    e, n = public_key
    
    if isinstance(plaintext, str):
        # Convert string ke integer
        plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    else:
        plaintext_int = plaintext
    
    # Pastikan plaintext < n
    if plaintext_int >= n:
        raise ValueError(f"Plaintext terlalu besar! Harus < {n}")
    
    # C = M^e mod n
    ciphertext = pow(plaintext_int, e, n)
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    """
    Decrypt menggunakan RSA
    ciphertext: integer
    private_key: (d, n)
    """
    d, n = private_key
    
    # M = C^d mod n
    plaintext_int = pow(ciphertext, d, n)
    
    return plaintext_int

def int_to_string(num):
    """Convert integer kembali ke string"""
    # Hitung byte length yang dibutuhkan
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode('utf-8', errors='ignore')

# ==== Testing ====
if __name__ == "__main__":
    print("=== Testing RSA Implementation ===\n")
    
    # Generate keypair
    public_key, private_key = generate_keypair(bits=16)
    print(f"\nPublic Key: {public_key}")
    print(f"Private Key: {private_key}")
    
    # Test enkripsi/dekripsi
    message = "HELLO123"
    print(f"\nOriginal Message: {message}")
    
    cipher = encrypt_rsa(message, public_key)
    print(f"Encrypted: {cipher}")
    
    decrypted_int = decrypt_rsa(cipher, private_key)
    decrypted_msg = int_to_string(decrypted_int)
    print(f"Decrypted: {decrypted_msg}")
    
    print(f"\nSuccess: {message == decrypted_msg}")