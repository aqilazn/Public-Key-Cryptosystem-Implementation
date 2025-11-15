# rsa_core.py
import random
import math

def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    def try_composite(a):
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            return False
        for _ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                return False
        return True
    for _ in range(k):
        a = random.randrange(2, n-2)
        if try_composite(a):
            return False
    return True

def generate_prime(bits=16):
    while True:
        candidate = random.getrandbits(bits) | 1 | (1 << (bits-1))
        if is_probable_prime(candidate):
            return candidate

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("modular inverse does not exist")
    return x % m

def generate_keypair(bits=512):
    # keep bits moderate so keys fit in Python int quickly
    while True:
        p = generate_prime(bits//2)
        q = generate_prime(bits//2)
        if p == q:
            continue
        n = p * q
        phi = (p-1)*(q-1)
        e = 65537
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return (e, n), (d, n)

def rsa_encrypt_int(m_int, pub):
    e, n = pub
    return pow(m_int, e, n)

def rsa_decrypt_int(c_int, priv):
    d, n = priv
    return pow(c_int, d, n)

def rsa_encrypt_bytes(msg_bytes: bytes, pub):
    m = int.from_bytes(msg_bytes, 'big')
    if m >= pub[1]:
        raise ValueError("message too large for key size")
    c = rsa_encrypt_int(m, pub)
    return str(c).encode()   # send decimal string bytes

def rsa_decrypt_bytes(cipher_bytes: bytes, priv):
    c = int(cipher_bytes.decode())
    m = rsa_decrypt_int(c, priv)
    # convert back to bytes — determine length
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, 'big')