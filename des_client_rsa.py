import socket
import json
import random
import string
import threading
import time
from des_core import text_to_bits, subkeys, encrypt_ecb, decrypt_ecb
from rsa_core import generate_keypair, encrypt_rsa, decrypt_rsa, int_to_string

SERVER_IP = input("Enter server IP: ").strip()
if not SERVER_IP:
    SERVER_IP = "127.0.0.1"
PORT = 5555

def generate_random_des_key(length=8):
    """Generate random DES key (8 bytes)"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def receive_messages(client_socket, des_keys, stop_event):
    """Thread untuk menerima pesan"""
    while not stop_event.is_set():
        try:
            data = client_socket.recv(8192).decode()
            if not data:
                print("\n[DISCONNECTED] Connection closed")
                stop_event.set()
                break
            
            # Decrypt pesan DES
            try:
                plaintext = decrypt_ecb(data, des_keys)
                print(f"\n[Peer] {plaintext}")
                print("You: ", end="", flush=True)
            except Exception as e:
                print(f"\n[ERROR] Decryption failed: {e}")
                
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n[ERROR] Receive error: {e}")
            break

def client_program():
    print("="*70)
    print(" "*20 + "DES SECURE CLIENT")
    print(" "*15 + "with E2E Encryption via RSA")
    print("="*70)
    print("\n[INFO] Messages are end-to-end encrypted")
    print("[INFO] Server cannot read your messages\n")
    
    # Connect to server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[1] Connecting to server {SERVER_IP}:{PORT}...")
    
    try:
        client_socket.connect((SERVER_IP, PORT))
        print(f"    Connected successfully!\n")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return
    
    print("[2] Waiting for role assignment from server...")
    
    # Receive role from server
    role_data = client_socket.recv(1024).decode()
    role_info = json.loads(role_data)
    role = role_info['role']
    
    des_key = None
    des_keys = None
    stop_event = threading.Event()
    
    try:
        if role == "CLIENT_1":
            print("[ROLE] You are Client 1 (Key Receiver)\n")
            
            # Generate RSA keypair
            print("[3] Generating RSA keypair...")
            my_public_key, my_private_key = generate_keypair(bits=512)
            e, n = my_public_key
            print(f"    Public Key: (e={e}, n={n})\n")
            
            # Send public key
            print("[4] Sending public key to server...")
            pubkey_data = json.dumps({"e": e, "n": n})
            client_socket.send(pubkey_data.encode())
            print("    Sent successfully!\n")
            
            print("[5] Waiting for encrypted DES key from Client 2...\n")
            
            # Receive encrypted DES key
            encrypted_data = client_socket.recv(4096).decode()
            encrypted_info = json.loads(encrypted_data)
            encrypted_des_key = int(encrypted_info['encrypted_des_key'])
            print(f"[6] Received encrypted DES key")
            print(f"    Encrypted: {str(encrypted_des_key)[:50]}...\n")
            
            # Decrypt DES key
            print("[7] Decrypting DES key with RSA private key...")
            decrypted_int = decrypt_rsa(encrypted_des_key, my_private_key)
            des_key = int_to_string(decrypted_int)
            
            # Ensure 8 characters
            if len(des_key) < 8:
                des_key = des_key.ljust(8, '0')
            elif len(des_key) > 8:
                des_key = des_key[:8]
            
            print(f"    Decrypted DES Key: '{des_key}'\n")
            
        else:  # CLIENT_2
            print("[ROLE] You are Client 2 (Key Generator)\n")
            
            # Receive Client 1's public key
            print("[3] Receiving Client 1's public key...")
            pubkey_data = client_socket.recv(4096).decode()
            client1_pubkey = json.loads(pubkey_data)
            e1 = client1_pubkey['e']
            n1 = client1_pubkey['n']
            peer_public_key = (e1, n1)
            print(f"    Client 1 Public Key: (e={e1}, n={n1})\n")
            
            # Generate DES key
            print("[4] Generating random DES key...")
            des_key = generate_random_des_key(8)
            print(f"    DES Key: '{des_key}'\n")
            
            # Encrypt DES key
            print("[5] Encrypting DES key with Client 1's RSA public key...")
            encrypted_des_key = encrypt_rsa(des_key, peer_public_key)
            print(f"    Encrypted: {str(encrypted_des_key)[:50]}...\n")
            
            # Send encrypted DES key
            print("[6] Sending encrypted DES key to Client 1...")
            encrypted_data = json.dumps({"encrypted_des_key": str(encrypted_des_key)})
            client_socket.send(encrypted_data.encode())
            print("    Sent successfully!\n")
    
    except Exception as e:
        print(f"[ERROR] Key exchange failed: {e}")
        import traceback
        traceback.print_exc()
        client_socket.close()
        return
    
    # Generate DES subkeys
    print("[8] Generating DES subkeys...")
    key_bits = text_to_bits(des_key)
    des_keys = subkeys(key_bits)
    print("    DES encryption ready!\n")
    
    print("="*70)
    print(" "*15 + "KEY EXCHANGE SUCCESSFUL!")
    print(" "*10 + "You can now chat securely with peer")
    print(" "*12 + "(Server cannot read messages)")
    print("="*70)
    print("\nType your messages below. Type 'exit' to quit.\n")
    
    # Start receive thread
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, des_keys, stop_event), daemon=True)
    receive_thread.start()
    
    # Main send loop
    try:
        while not stop_event.is_set():
            msg = input("You: ")
            
            if stop_event.is_set():
                break
                
            if msg.strip().lower() == "exit":
                client_socket.send("exit".encode())
                print("\n[INFO] Closing connection...")
                break
            
            if msg.strip():
                # Encrypt and send
                try:
                    ciphertext = encrypt_ecb(msg, des_keys)
                    client_socket.send(ciphertext.encode())
                except Exception as e:
                    print(f"[ERROR] Failed to send: {e}")
                    break
    
    except KeyboardInterrupt:
        print("\n\n[INFO] Interrupted by user")
    
    finally:
        stop_event.set()
        client_socket.close()
        print("\n[CLOSED] Connection closed")

if __name__ == "__main__":
    client_program()