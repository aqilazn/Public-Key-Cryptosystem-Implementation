import socket
import json
from des_core import * 
from rsa_core import generate_keypair, decrypt_rsa, int_to_string

HOST = "0.0.0.0"
PORT = 5555

def server_program():
    print("=== DES Secure Server with RSA Key Exchange ===\n")
    
    # 1. Generate RSA keypair
    print("[1] Generating RSA keypair...")
    public_key, private_key = generate_keypair(bits=32)  
    e, n = public_key
    print(f"    Public Key: (e={e}, n={n})")
    print(f"    Private Key: (d={private_key[0]}, n={n})\n")
    
    # 2. Setup socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"[2] Server listening on {HOST}:{PORT}...")
    print("    Waiting for client connection...\n")
    
    conn, addr = server_socket.accept()
    print(f"[3] Client connected from {addr}\n")
    
    # 3. Kirim public key ke client
    print("[4] Sending public key to client...")
    public_key_data = json.dumps({"e": e, "n": n})
    conn.send(public_key_data.encode())
    print(f"    Sent: {public_key_data}\n")
    
    # 4. Terima encrypted DES key dari client
    print("[5] Waiting for encrypted DES key from client...")
    encrypted_key_data = conn.recv(4096).decode()
    encrypted_des_key = int(encrypted_key_data)
    print(f"    Received encrypted key: {encrypted_des_key}")
    
    # 5. Decrypt DES key menggunakan RSA private key
    print("[6] Decrypting DES key with RSA private key...")
    decrypted_key_int = decrypt_rsa(encrypted_des_key, private_key)
    des_key = int_to_string(decrypted_key_int)
    
    # Pastikan panjang 8 karakter
    if len(des_key) < 8:
        des_key = des_key.ljust(8, '0')
    elif len(des_key) > 8:
        des_key = des_key[:8]
    
    print(f"    Decrypted DES Key: '{des_key}'")
    
    # 6. Generate DES subkeys
    key_bits = text_to_bits(des_key)
    keys = subkeys(key_bits)
    print(f"    DES subkeys generated!\n")
    
    print("="*60)
    print("RSA KEY EXCHANGE COMPLETED! Starting secure DES communication...")
    print("="*60 + "\n")
    
    # 7. Komunikasi DES normal
    while True:
        data = conn.recv(4096).decode()
        if not data:
            break
        if data == "exit":
            print("\n[Client disconnected]")
            break
        
        # Decrypt pesan dari client
        try:
            decrypted = decrypt_ecb(data, keys)
            print(f"[Client] Encrypted: {data[:32]}...")
            print(f"         Decrypted: {decrypted}\n")
        except Exception as ex:
            print(f"[Error] Decryption failed: {ex}")
            continue
        
        # Kirim response
        response = input("Server reply: ")
        if response.lower() == "exit":
            conn.send("exit".encode())
            break
            
        cipher_resp = encrypt_ecb(response, keys)
        conn.send(cipher_resp.encode())
        print(f"[Server] Sent encrypted response\n")
    
    conn.close()
    server_socket.close()
    print("\n[Connection closed]")

if __name__ == "__main__":
    server_program()