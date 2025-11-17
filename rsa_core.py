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

def generate_keypair(bits=512):
    """
    Generate RSA key pair
    Returns: (public_key, private_key) where public_key=(e,n), private_key=(d,n)
    """
    print(f"[RSA] Generating {bits}-bit keypair...")
    
    # 1. Generate dua prime number p dan q
    p = generate_prime(bits//2)
    q = generate_prime(bits//2)
    while p == q:
        q = generate_prime(bits//2)
    
    # 2. Hitung n = p * q
    n = p * q
    
    # 3. Hitung phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)
    
    # 4. Pilih e (biasanya 65537)
    e = 65537
    if e >= phi or gcd(e, phi) != 1:
        e = random.randrange(2, phi)
        while gcd(e, phi) != 1:
            e = random.randrange(2, phi)
    
    # 5. Hitung d = e^-1 mod phi
    d = mod_inverse(e, phi)
    
    print(f"[RSA] Keypair generated successfully")
    
    return ((e, n), (d, n))

def encrypt_rsa(plaintext, public_key):
    """Encrypt integer atau string dengan RSA"""
    e, n = public_key
    
    if isinstance(plaintext, str):
        plaintext_int = int.from_bytes(plaintext.encode('latin-1'), 'big')
    elif isinstance(plaintext, bytes):
        plaintext_int = int.from_bytes(plaintext, 'big')
    else:
        plaintext_int = plaintext
    
    if plaintext_int >= n:
        raise ValueError(f"Plaintext terlalu besar untuk key size! Max: {n}")
    
    ciphertext = pow(plaintext_int, e, n)
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    """Decrypt RSA ciphertext"""
    d, n = private_key
    plaintext_int = pow(ciphertext, d, n)
    return plaintext_int

def int_to_bytes(num, length=8):
    """Convert integer ke bytes dengan panjang tertentu"""
    if num == 0:
        return b'\x00' * length
    byte_length = max((num.bit_length() + 7) // 8, length)
    return num.to_bytes(byte_length, 'big')[-length:]

def int_to_string(num):
    """Convert integer kembali ke string"""
    if num == 0:
        return ""
    byte_length = (num.bit_length() + 7) // 8
    return num.to_bytes(byte_length, 'big').decode('latin-1', errors='ignore')