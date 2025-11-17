import socket
import threading
import json
import time

HOST = "0.0.0.0"
PORT = 5555

clients = []  # List of (conn, addr, name)
lock = threading.Lock()

def broadcast_message(sender_conn, message):
    """Relay encrypted message to other clients"""
    with lock:
        for conn, addr, name in clients:
            if conn != sender_conn:
                try:
                    conn.send(message.encode() if isinstance(message, str) else message)
                except Exception as e:
                    print(f"[ERROR] Failed to send to {name}: {e}")

def handle_communication(conn, addr, name):
    """Handle regular message relay after key exchange"""
    print(f"\n[CHAT START] {name} ready for secure messaging\n")
    
    try:
        while True:
            data = conn.recv(8192)
            if not data:
                print(f"[DISCONNECT] {name} disconnected")
                break
            
            message = data.decode()
            
            if message.strip().lower() == "exit":
                print(f"[EXIT] {name} is leaving")
                break
            
            # Relay encrypted message
            print(f"[RELAY] {name} → Peer (encrypted, length: {len(message)})")
            broadcast_message(conn, message)
    
    except Exception as e:
        print(f"[ERROR] {name} handler error: {e}")
    
    finally:
        with lock:
            clients[:] = [(c, a, n) for c, a, n in clients if c != conn]
        print(f"[CLOSED] {name} disconnected\n")

def server_program():
    print("="*70)
    print(" "*15 + "DES SECURE RELAY SERVER")
    print(" "*10 + "with RSA-Based Key Exchange")
    print("="*70)
    print("\n[INFO] Server hanya sebagai relay/perantara")
    print("[INFO] Server TIDAK dapat membaca plaintext pesan\n")
    
    # Setup socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    
    print(f"[1] Server listening on {HOST}:{PORT}")
    print(f"    Waiting for 2 clients...\n")
    print("="*70 + "\n")
    
    # Accept Client 1
    print("[WAITING] Waiting for Client 1...")
    conn1, addr1 = server_socket.accept()
    name1 = f"Client-1"
    
    with lock:
        clients.append((conn1, addr1, name1))
    
    print(f"[CONNECTED] {name1} from {addr1}")
    
    # Assign role to Client 1
    role_data = json.dumps({"role": "CLIENT_1"})
    conn1.send(role_data.encode())
    print(f"[ASSIGNED] {name1} assigned as Key Receiver")
    print(f"[INFO] Waiting for Client 2...\n")
    
    # Accept Client 2
    print("[WAITING] Waiting for Client 2...")
    conn2, addr2 = server_socket.accept()
    name2 = f"Client-2"
    
    with lock:
        clients.append((conn2, addr2, name2))
    
    print(f"[CONNECTED] {name2} from {addr2}")
    
    # Assign role to Client 2
    role_data = json.dumps({"role": "CLIENT_2"})
    conn2.send(role_data.encode())
    print(f"[ASSIGNED] {name2} assigned as Key Generator\n")
    
    print("="*70)
    print("[SUCCESS] Both clients connected!")
    print("[INFO] Starting RSA key exchange protocol...")
    print("="*70 + "\n")
    
    # Key Exchange Protocol
    try:
        # Step 1: Receive public key from Client 1
        print("[STEP 1] Receiving public key from Client 1...")
        pubkey_data = conn1.recv(4096).decode()
        pubkey_json = json.loads(pubkey_data)
        print(f"          Received: e={pubkey_json['e']}")
        
        # Step 2: Forward public key to Client 2
        print("[STEP 2] Forwarding public key to Client 2...")
        conn2.send(pubkey_data.encode())
        print("          Forwarded successfully")
        
        # Step 3: Receive encrypted DES key from Client 2
        print("[STEP 3] Receiving encrypted DES key from Client 2...")
        encrypted_des_data = conn2.recv(4096).decode()
        encrypted_json = json.loads(encrypted_des_data)
        
        # Check if key exists
        if 'encrypted_des_key' not in encrypted_json:
            raise KeyError("encrypted_des_key not found in Client 2 response")
        
        enc_key_str = str(encrypted_json['encrypted_des_key'])
        print(f"          Received: {enc_key_str[:50]}...")
        
        # Step 4: Forward encrypted DES key to Client 1
        print("[STEP 4] Forwarding encrypted DES key to Client 1...")
        conn1.send(encrypted_des_data.encode())
        print("          Forwarded successfully\n")
        
        print("="*70)
        print("[KEY EXCHANGE COMPLETE]")
        print("  • Both clients now share the same DES key")
        print("  • Server CANNOT decrypt their messages")
        print("  • Secure end-to-end communication established!")
        print("="*70 + "\n")
        
        # Start message relay threads
        t1 = threading.Thread(target=handle_communication, args=(conn1, addr1, name1), daemon=True)
        t2 = threading.Thread(target=handle_communication, args=(conn2, addr2, name2), daemon=True)
        
        t1.start()
        t2.start()
        
        t1.join()
        t2.join()
        
    except Exception as e:
        print(f"[ERROR] Key exchange failed: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        conn1.close()
        conn2.close()
        server_socket.close()
        print("\n[SHUTDOWN] Server closed")

if __name__ == "__main__":
    try:
        server_program()
    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Server shutting down...")
    except Exception as e:
        print(f"\n[ERROR] Server error: {e}")
        import traceback
        traceback.print_exc()