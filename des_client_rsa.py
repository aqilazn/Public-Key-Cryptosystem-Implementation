import socket
import json
import random
import string
from des_core import * 
from rsa_core import encrypt_rsa

SERVER_IP = input("Enter server IP: ")
PORT = 5555

def generate_random_key(length=8):
    """Generate random DES key"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def client_program():
    print("=== DES Secure Client with RSA Key Exchange ===\n")
    
    # 1. Connect ke server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[1] Connecting to server {SERVER_IP}:{PORT}...")
    client_socket.connect((SERVER_IP, PORT))
    print(f"    Connected!\n")
    
    # 2. Terima public key dari server
    print("[2] Receiving public key from server...")
    public_key_data = client_socket.recv(4096).decode()
    public_key_json = json.loads(public_key_data)
    e = public_key_json["e"]
    n = public_key_json["n"]
    public_key = (e, n)
    print(f"    Received Public Key: (e={e}, n={n})\n")
    
    # 3. Generate random DES key
    print("[3] Generating random DES key...")
    des_key = generate_random_key(8)
    print(f"    Generated DES Key: '{des_key}'\n")
    
    # 4. Encrypt DES key dengan RSA public key
    print("[4] Encrypting DES key with RSA public key...")
    encrypted_des_key = encrypt_rsa(des_key, public_key)
    print(f"    Encrypted DES Key: {encrypted_des_key}\n")
    
    # 5. Kirim encrypted DES key ke server
    print("[5] Sending encrypted DES key to server...")
    client_socket.send(str(encrypted_des_key).encode())
    print(f"    Sent!\n")
    
    # 6. Generate DES subkeys
    key_bits = text_to_bits(des_key)
    keys = subkeys(key_bits)
    print("[6] DES subkeys generated!\n")
    
    print("="*60)
    print("RSA KEY EXCHANGE COMPLETED! Starting secure DES communication...")
    print("="*60 + "\n")
    
    # 7. Komunikasi DES normal
    while True:
        msg = input("Client message: ")
        if msg.lower() == "exit":
            client_socket.send("exit".encode())
            break
        
        # Encrypt dan kirim
        cipher_text = encrypt_ecb(msg, keys)
        client_socket.send(cipher_text.encode())
        print(f"[Client] Sent encrypted message\n")
        
        # Terima response
        data = client_socket.recv(4096).decode()
        if not data or data == "exit":
            print("\n[Server disconnected]")
            break
        
        # Decrypt response
        try:
            decrypted = decrypt_ecb(data, keys)
            print(f"[Server] Encrypted: {data[:32]}...")
            print(f"         Decrypted: {decrypted}\n")
        except Exception as ex:
            print(f"[Error] Decryption failed: {ex}\n")
    
    client_socket.close()
    print("\n[Connection closed]")

if __name__ == "__main__":
    client_program()