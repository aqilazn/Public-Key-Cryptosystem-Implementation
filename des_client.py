# des_client.py
import socket
import os
from rsa_core import rsa_encrypt_bytes
from des_core import text_to_bits, subkeys, encrypt_ecb, decrypt_ecb

SERVER_IP = input("Masukkan IP server: ").strip()
PORT = 5555

def client_program():
    print("=== DES Secure Client ===")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER_IP, PORT))
    print(f"Terhubung ke server {SERVER_IP}:{PORT}")

    # 1) Terima public key RSA dari server
    pk = s.recv(1024).decode()
    e, n = map(int, pk.split(","))
    pubkey = (e, n)
    print(f"[RSA] Received server public key: {pubkey}")

    # 2) Generate DES key (8 bytes)
    des_key = os.urandom(8)
    des_key_text = des_key.decode('latin-1', errors='ignore')

    # 3) Encrypt DES key with server public key and send
    enc = rsa_encrypt_bytes(des_key, pubkey)
    s.send(enc)
    print("[RSA] Encrypted DES key sent to server. DES-based chat ready.")

    # prepare DES subkeys
    key_bits = text_to_bits(des_key_text)
    keys = subkeys(key_bits)

    # Start receiving thread
    import threading
    def listen():
        while True:
            try:
                data = s.recv(8192)
                if not data:
                    print("[*] connection closed by server")
                    break
                cipher_hex = data.decode()
                try:
                    plaintext = decrypt_ecb(cipher_hex, keys)
                except Exception as e:
                    print(f"[!] decrypt error: {e}")
                    continue
                if plaintext.strip().lower() == "exit":
                    print("[*] The other side exited. Closing.")
                    break
                print(f"\n[Peer] {plaintext}\nKirim pesan: ", end='', flush=True)
            except Exception as e:
                print(f"[!] listen error: {e}")
                break

    t = threading.Thread(target=listen, daemon=True)
    t.start()

    # main send loop
    try:
        while True:
            msg = input("Kirim pesan: ")
            cipher = encrypt_ecb(msg, keys)
            s.send(cipher.encode())
            if msg.strip().lower() == "exit":
                break
    except KeyboardInterrupt:
        try:
            s.send(encrypt_ecb("exit", keys).encode())
        except:
            pass
    finally:
        s.close()
        print("Koneksi ditutup.")

if __name__ == "__main__":
    client_program()