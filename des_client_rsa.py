import socket
import json
import random
import string
import threading
import time
from des_core import text_to_bits, subkeys, encrypt_ecb, decrypt_ecb
from rsa_core import generate_keypair, encrypt_rsa, decrypt_rsa, int_to_string
from signature_core import sign_message, verify_signature

SERVER_IP = input("Enter server IP: ").strip()
if not SERVER_IP:
    SERVER_IP = "127.0.0.1"
PORT = 5555

def generate_random_des_key(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def receive_messages(client_socket, des_keys, peer_public_key, stop_event):
    while not stop_event.is_set():
        try:
            data = client_socket.recv(8192).decode()
            if not data:
                print("\n[DISCONNECTED] Connection closed")
                stop_event.set()
                break

            try:
                message_data = json.loads(data)
                ciphertext = message_data['ciphertext']
                signature = int(message_data['signature'])

                plaintext = decrypt_ecb(ciphertext, des_keys)

                is_valid = verify_signature(plaintext, signature, peer_public_key)
                
                if is_valid:
                    print(f"\n[Peer] {plaintext} ✓")
                else:
                    print(f"\n[Peer] {plaintext} ⚠️ SIGNATURE INVALID!")
                
                print("You: ", end="", flush=True)
                
            except json.JSONDecodeError:
                plaintext = decrypt_ecb(data, des_keys)
                print(f"\n[Peer] {plaintext} (no signature)")
                print("You: ", end="", flush=True)
            except Exception as e:
                print(f"\n[ERROR] Decryption failed: {e}")
                
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n[ERROR] Receive error: {e}")
            break

def client_program():
    print("="*70)
    print(" "*15 + "DES SECURE CLIENT v2.0")
    print(" "*10 + "with E2E Encryption + Digital Signature")
    print("="*70)
    print("\n[INFO] Messages are end-to-end encrypted")
    print("[INFO] Messages are digitally signed for authentication")
    print("[INFO] Server cannot read your messages\n")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[1] Connecting to server {SERVER_IP}:{PORT}...")
    
    try:
        client_socket.connect((SERVER_IP, PORT))
        print(f"    Connected successfully!\n")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")
        return
    
    print("[2] Waiting for role assignment from server...")

    role_data = client_socket.recv(1024).decode()
    role_info = json.loads(role_data)
    role = role_info['role']
    
    des_key = None
    des_keys = None
    my_public_key = None
    my_private_key = None
    peer_public_key = None
    stop_event = threading.Event()
    
    try:
        if role == "CLIENT_1":
            print("[ROLE] You are Client 1 (Key Receiver)\n")

            print("[3] Generating RSA keypair...")
            my_public_key, my_private_key = generate_keypair(bits=512)
            e, n = my_public_key
            print(f"    Public Key: (e={e}, n={n})\n")

            print("[4] Sending public key to server...")
            pubkey_data = json.dumps({"e": e, "n": n})
            client_socket.send(pubkey_data.encode())
            print("    Sent successfully!\n")
            
            print("[5] Waiting for encrypted DES key from Client 2...\n")

            encrypted_data = client_socket.recv(4096).decode()
            encrypted_info = json.loads(encrypted_data)
            encrypted_des_key = int(encrypted_info['encrypted_des_key'])

            e2 = encrypted_info['sender_public_key']['e']
            n2 = encrypted_info['sender_public_key']['n']
            peer_public_key = (e2, n2)
            
            print(f"[6] Received encrypted DES key")
            print(f"    Encrypted: {str(encrypted_des_key)[:50]}...")
            print(f"    Peer Public Key: (e={e2}, n={n2})\n")

            print("[7] Decrypting DES key with RSA private key...")
            decrypted_int = decrypt_rsa(encrypted_des_key, my_private_key)
            des_key = int_to_string(decrypted_int)

            if len(des_key) < 8:
                des_key = des_key.ljust(8, '0')
            elif len(des_key) > 8:
                des_key = des_key[:8]
            
            print(f"    Decrypted DES Key: '{des_key}'\n")
            
        else:  #client 2
            print("[ROLE] You are Client 2 (Key Generator)\n")

            print("[3] Generating RSA keypair for signing...")
            my_public_key, my_private_key = generate_keypair(bits=512)
            e, n = my_public_key
            print(f"    Public Key: (e={e}, n={n})\n")

            print("[4] Receiving Client 1's public key...")
            pubkey_data = client_socket.recv(4096).decode()
            client1_pubkey = json.loads(pubkey_data)
            e1 = client1_pubkey['e']
            n1 = client1_pubkey['n']
            peer_public_key = (e1, n1)
            print(f"    Client 1 Public Key: (e={e1}, n={n1})\n")

            print("[5] Generating random DES key...")
            des_key = generate_random_des_key(8)
            print(f"    DES Key: '{des_key}'\n")

            print("[6] Encrypting DES key with Client 1's RSA public key...")
            encrypted_des_key = encrypt_rsa(des_key, peer_public_key)
            print(f"    Encrypted: {str(encrypted_des_key)[:50]}...\n")

            print("[7] Sending encrypted DES key to Client 1...")
            encrypted_data = json.dumps({
                "encrypted_des_key": str(encrypted_des_key),
                "sender_public_key": {"e": e, "n": n}
            })
            client_socket.send(encrypted_data.encode())
            print("    Sent successfully!\n")
    
    except Exception as e:
        print(f"[ERROR] Key exchange failed: {e}")
        import traceback
        traceback.print_exc()
        client_socket.close()
        return

    print("[8] Generating DES subkeys...")
    key_bits = text_to_bits(des_key)
    des_keys = subkeys(key_bits)
    print("    DES encryption ready!\n")
    
    print("="*70)
    print(" "*12 + "KEY EXCHANGE SUCCESSFUL!")
    print(" "*7 + "You can now chat securely with peer")
    print(" "*5 + "Messages are encrypted + digitally signed")
    print("="*70)
    print("\n[SIGNATURE] ✓ = Valid signature")
    print("[SIGNATURE] ⚠️  = Invalid/tampered message\n")
    print("Type your messages below. Type 'exit' to quit.\n")

    receive_thread = threading.Thread(
        target=receive_messages, 
        args=(client_socket, des_keys, peer_public_key, stop_event), 
        daemon=True
    )
    receive_thread.start()

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
                try:
                    ciphertext = encrypt_ecb(msg, des_keys)

                    signature = sign_message(msg, my_private_key)

                    signed_message = json.dumps({
                        'ciphertext': ciphertext,
                        'signature': str(signature)
                    })

                    client_socket.send(signed_message.encode())
                    
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