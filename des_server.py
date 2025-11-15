# des_server.py
import socket
import threading
from rsa_core import generate_keypair, rsa_decrypt_bytes
from des_core import text_to_bits, subkeys, decrypt_ecb, encrypt_ecb

HOST = "0.0.0.0"
PORT = 5555

clients = []        # list of (conn, addr)
client_info = {}    # conn -> {'des_key_text': str, 'des_keys': list}
lock = threading.Lock()

def handle_client(conn, addr, privkey, pubkey):
    try:
        print(f"[{addr}] connected — starting RSA handshake")

        # 1) Send public key to client as "e,n"
        conn.send(f"{pubkey[0]},{pubkey[1]}".encode())

        # 2) Receive encrypted DES key from client
        enc_des = conn.recv(4096)
        if not enc_des:
            print(f"[{addr}] handshake failed (no data)")
            remove_client(conn)
            return

        des_key_bytes = rsa_decrypt_bytes(enc_des, privkey)
        # interpret DES key as latin-1 text (8 bytes)
        des_key_text = des_key_bytes.decode('latin-1', errors='ignore')
        key_bits = text_to_bits(des_key_text)
        keys = subkeys(key_bits)

        with lock:
            client_info[conn] = {'des_key_text': des_key_text, 'des_keys': keys}
        print(f"[{addr}] RSA handshake complete. DES key stored.")

        # If two clients connected, notify
        wait_for_pair()

        # Listen for encrypted messages (hex strings) from this client
        while True:
            data = conn.recv(8192)
            if not data:
                print(f"[{addr}] disconnected")
                break
            cipher_hex = data.decode()
            # decrypt using this client's DES key
            keys_here = client_info[conn]['des_keys']
            try:
                plaintext = decrypt_ecb(cipher_hex, keys_here)
            except Exception as e:
                print(f"[{addr}] decrypt error: {e}")
                continue

            print(f"[{addr}] → {plaintext}")

            if plaintext.strip().lower() == "exit":
                # inform other client and close
                other = get_other_client(conn)
                if other:
                    # send an encrypted "exit" to other
                    other_keys = client_info[other]['des_keys']
                    other.send(encrypt_ecb("exit", other_keys).encode())
                break

            # relay: encrypt plaintext with other client's DES key and send
            other = get_other_client(conn)
            if other:
                other_keys = client_info[other]['des_keys']
                cipher_for_other = encrypt_ecb(plaintext, other_keys)
                try:
                    other.send(cipher_for_other.encode())
                except Exception as e:
                    print(f"Failed to send to other client: {e}")

    except Exception as e:
        print(f"[{addr}] handler exception: {e}")
    finally:
        remove_client(conn)
        conn.close()
        print(f"[{addr}] connection closed")

def wait_for_pair():
    # simple notification log when two clients are ready
    with lock:
        if len(clients) >= 2 and all(c in client_info for c,_ in clients[:2]):
            print("[Server] Dua client sudah handshake. Relay aktif antara kedua client.")

def get_other_client(conn):
    with lock:
        if len(clients) < 2:
            return None
        # first two only
        c1, _ = clients[0]
        c2, _ = clients[1]
        return c2 if conn == c1 else (c1 if conn == c2 else None)

def remove_client(conn):
    with lock:
        # remove from clients and client_info
        idx = None
        for i, (c,a) in enumerate(clients):
            if c == conn:
                idx = i
                break
        if idx is not None:
            clients.pop(idx)
        if conn in client_info:
            client_info.pop(conn)

def server_program():
    print("=== DES Relay Server (2-client mode) with RSA Key Distribution ===")
    print("[*] Generating RSA keypair...")
    pubkey, privkey = generate_keypair(bits=512)  # moderate size for demo
    print("[*] RSA public key ready.")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[*] Listening on {HOST}:{PORT} — waiting for 2 clients")

    try:
        while True:
            conn, addr = server_socket.accept()
            with lock:
                clients.append((conn, addr))
            t = threading.Thread(target=handle_client, args=(conn, addr, privkey, pubkey), daemon=True)
            t.start()

            with lock:
                if len(clients) > 2:
                    print("[Server] Warning: lebih dari 2 koneksi terhubung — server hanya merelay antara dua pertama.")
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    server_program()