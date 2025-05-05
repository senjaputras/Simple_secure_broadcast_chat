import socket
import threading
from crypt_module import *

server_priv_key, server_verif_key = generate_ecdsa()
ec_server = generate_ecdh(server_priv_key)
server_pub_bytes = server_verif_key.to_string()

HOST = '0.0.0.0'
PORT = 5000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()

clients = {}  # socket: {"public_key": ..., "username": ..., "des_key": ...}

def handle_client(conn, addr):
    try:
        client_pub_bytes = conn.recv(1024)
        username = conn.recv(1024).decode().strip()
        # Set up ECDH with this client
        ecdh = generate_ecdh(server_priv_key)
        des_key = derive_shared_key(ecdh, client_pub_bytes, username)

        clients[conn] = {
            "public_key": client_pub_bytes,
            "username": username,
            "des_key": des_key
        }

        conn.sendall(server_pub_bytes)
        print ("\n")
        print (f"[+] {username} connected from {addr}.")
        print ("Public Key:")
        print (client_pub_bytes)
        print ("\n")
        while True:
            data = conn.recv(2048)
            if not data:
                break
            broadcast_message(data, sender=conn)
    except Exception as e:
        print(f"[!] Error with client {addr}: {e}")
    finally:
        print(f"[-] Disconnected: {addr}")
        clients.pop(conn, None)
        conn.close()


def broadcast_message(encrypted_msg, sender):
    sender_info = clients[sender]
    decrypted = des_decrypt_with_key(sender_info["des_key"], encrypted_msg)

    # Parse and verify original sender’s signature
    signature = decrypted[:64]
    msg_hash = decrypted[64:96]
    message = decrypted[96:]

    # Optional: verify original sender's sig
    if not verify_signature(sender_info["public_key"], signature, msg_hash):
        print(f"[!] Invalid signature from {sender_info['username']}")
        return

    #print(f"[>] {sender_info['username']} says: {message.decode()}")
    print(f"[>] {message.decode()}")
    # Relay message as server
    server_msg = message
    server_hash = hash_message(server_msg)
    server_signature = signing(server_priv_key, server_hash)
    payload = server_signature + server_hash + server_msg

    for conn, info in clients.items():
        if conn == sender:
            continue
        try:
            encrypted = des_encrypt(info["des_key"], payload)
            conn.sendall(encrypted)
        except Exception as e:
            print(f"[!] Failed to send to {info['username']}: {e}")

print(f"[*] Server running on {HOST}:{PORT}")
while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
