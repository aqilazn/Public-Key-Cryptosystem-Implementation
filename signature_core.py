import hashlib
from rsa_core import encrypt_rsa, decrypt_rsa

def hash_message(message):
    if isinstance(message, str):
        message = message.encode('utf-8')

    hash_obj = hashlib.sha256(message)
    hash_hex = hash_obj.hexdigest()

    hash_int = int(hash_hex, 16)
    
    return hash_int

def sign_message(message, private_key):
    message_hash = hash_message(message)

    d, n = private_key

    message_hash = message_hash % n
    
    signature = pow(message_hash, d, n)
    
    return signature

def verify_signature(message, signature, public_key):
    try:
        computed_hash = hash_message(message)

        e, n = public_key
        
        computed_hash = computed_hash % n
        
        recovered_hash = pow(signature, e, n)
 
        return computed_hash == recovered_hash
    
    except Exception as e:
        print(f"[SIGNATURE] Verification error: {e}")
        return False

def create_signed_message(plaintext, ciphertext, private_key):
    signature = sign_message(plaintext, private_key)
    
    return {
        'ciphertext': ciphertext,
        'signature': str(signature)
    }

def verify_signed_message(plaintext, signature, public_key):
    try:
        signature_int = int(signature)
        return verify_signature(plaintext, signature_int, public_key)
    except Exception as e:
        print(f"[SIGNATURE] Verification failed: {e}")
        return False