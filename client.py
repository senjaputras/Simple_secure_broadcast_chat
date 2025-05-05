import socket
import threading
from crypto_utils import *

username = input("Enter your username: ").strip()

# Keys and ECDH setup
client_sk, client_vk = generate_keys()
ecdh = init_ecdh(client_sk)
client_pub_bytes = client_vk.to_string()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('ServerIPAddress', 5000)) #Change ServerIPAddress, to IPv4 your server

s.sendall(client_pub_bytes)
print("[✓] Send client pub key to server")
print (client_pub_bytes)
s.sendall(username.encode())

server_pub_bytes = s.recv(1024)
print("\n[✓] Server Pub Key Received!")
des_key = derive_shared_key(ecdh, server_pub_bytes, username)
print (server_pub_bytes)
print ("\nShared Key from ECDH function for DES KEY:")
print (des_key)
print("[✓] Connected to server. Type 'exit' to quit.\n")


def recv_msg(sock):
    while True:
        try:
            data = sock.recv(2048)
            if not data:
                break
            decrypted = des_decrypt_with_key(des_key, data)
            signature = decrypted[:64]
            msg_hash = decrypted[64:96]
            message = decrypted[96:]
            if verify_signature(server_pub_bytes, signature, msg_hash):
                print(f"\n[+] Server: {message.decode()}")
        except Exception as e:
            print("[!] Disconnected from server.", e)
            break


def send_messages(sock):
    while True:
        msg = input("You: ")
        if msg.strip().lower() == "exit":
            break
        full_message = f"{username}: {msg}".encode()
        msg_hash = hash_message(full_message)
        signature = sign_hash(client_sk, msg_hash)
        payload = signature + msg_hash + full_message
        print ("\nmessage hash:")
        print (msg_hash)
        print ("\nSign the Hash:")
        print (signature)
        print ("\nconcate H||Sign||M:")
        print (msg_hash+signature+full_message)

        encrypted = des_encrypt(des_key, payload)
        s.sendall(encrypted)

threading.Thread(target=recv_msg, args=(s,), daemon=True).start()
send_messages(s)

