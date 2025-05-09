import socket
import threading
import json
import time
from cryptography.fernet import Fernet

# Shared symmetric key (for demo purposes, ideally this should be exchanged securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Basic peer structure
peers = set()

# Message handling
def handle_client(conn, addr):
    while True:
        try:
            encrypted_msg = conn.recv(4096)
            if not encrypted_msg:
                break
            decrypted_msg = cipher.decrypt(encrypted_msg).decode()
            msg_data = json.loads(decrypted_msg)
            print(f"[{msg_data['from']}] {msg_data['message']}")

            # Broadcast message to other peers
            for peer in peers.copy():
                if peer != addr:
                    try:
                        send_message(peer, msg_data["message"], msg_data["from"])
                    except:
                        peers.discard(peer)

        except Exception as e:
            print(f"Connection error with {addr}: {e}")
            break
    conn.close()

# Send encrypted message
def send_message(peer, message, sender):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(peer)
        msg = json.dumps({'from': sender, 'message': message})
        encrypted_msg = cipher.encrypt(msg.encode())
        s.sendall(encrypted_msg)

# Listen for connections
def start_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', port))
    server.listen()
    print(f"[LISTENING] Peer running on port {port}")

    while True:
        conn, addr = server.accept()
        peers.add(addr)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

# Connect to a peer
def connect_to_peer(host, port):
    try:
        peers.add((host, port))
        send_message((host, port), f"Hello from {MY_PORT}", f"Peer-{MY_PORT}")
        print(f"Connected to {(host, port)}")
    except:
        print(f"Failed to connect to {(host, port)}")

# Input loop
def input_loop():
    while True:
        msg = input()
        for peer in peers.copy():
            try:
                send_message(peer, msg, f"Peer-{MY_PORT}")
            except:
                peers.discard(peer)

# User-defined port
MY_PORT = int(input("Enter port to run this peer on: "))
bootstrap_host = input("Enter bootstrap peer IP (or blank): ")
bootstrap_port = input("Enter bootstrap peer port (or blank): ")

# Start listener
threading.Thread(target=start_server, args=(MY_PORT,), daemon=True).start()

# Bootstrap
if bootstrap_host and bootstrap_port:
    connect_to_peer(bootstrap_host, int(bootstrap_port))

# Start chat
input_loop()
