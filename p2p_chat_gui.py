import socket
import threading
import json
import tkinter as tk
from tkinter import scrolledtext
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import base64
import time
import queue
import uuid
import random # Import random for selecting peers to try reconnecting to

# --- Encryption Setup (Symmetric for Messages) ---
# This key is shared among all peers for group chat confidentiality (limited)
# REPLACE THIS WITH THE KEY YOU GENERATED EARLIER
SHARED_SYMMETRIC_KEY = b'ASJRJvCG2iKsCNu1fFVJ5IeFcS94hNkFazynToWHgDk=' # Use your actual key
symmetric_cipher = Fernet(SHARED_SYMMETRIC_KEY)

# --- Asymmetric Key Setup (for Identity and Signing) ---
MY_PRIVATE_KEY = None
MY_PUBLIC_KEY_SERIALIZED = None

# --- Network and Peer Setup ---
peers = {} # {(ip, listening_port): public_key_string} - Currently reachable peers
unreachable_peers = {} # {(ip, listening_port): public_key_string} - Peers we lost contact with
MY_PORT = 0
MY_NAME = ""

# --- Message Deduplication ---
seen_message_ids = set() # Store IDs of messages we have already processed

# Simple cleanup for seen_message_ids (remove old IDs)
def cleanup_seen_message_ids():
    global seen_message_ids
    print(f"Cleaning up seen_message_ids. Before: {len(seen_message_ids)}")
    seen_message_ids.clear()
    print(f"After cleanup: {len(seen_message_ids)}")
    # Reschedule cleanup
    # --- FIX: Use the correct way to set daemon for compatibility ---
    cleanup_timer_obj = threading.Timer(300, cleanup_seen_message_ids)
    cleanup_timer_obj.daemon = True # Set daemon attribute after creation
    cleanup_timer_obj.start() # Start the timer


# Start the initial cleanup timer at the module level
# --- FIX: Use the correct way to set daemon for compatibility ---
initial_cleanup_timer_obj = threading.Timer(300, cleanup_seen_message_ids)
initial_cleanup_timer_obj.daemon = True # Set daemon attribute after creation
initial_cleanup_timer_obj.start() # Start the timer


# --- GUI Setup ---
class ChatGUI:
    def __init__(self, master):
        self.master = master
        self.master.title(f"P2P Chat - {MY_NAME}")
        self.chat_display = scrolledtext.ScrolledText(master, state='disabled', width=60, height=20)
        self.chat_display.pack(padx=10, pady=10)

        self.msg_entry = tk.Entry(master, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=(10, 0), pady=(0, 10))
        self.msg_entry.bind("<Return>", self.send_msg)

        self.send_btn = tk.Button(master, text="Send", command=self.send_msg)
        self.send_btn.pack(side=tk.LEFT, padx=(5, 10), pady=(0, 10))

        self.message_queue = queue.Queue()
        self.master.after(100, self.process_message_queue)


    def display_message(self, sender, message):
        """Displays a message in the chat display (called from main thread)."""
        print(f"Attempting to display message in GUI: {sender}: {message}")
        self.chat_display.configure(state='normal')
        self.chat_display.insert(tk.END, f"{sender}: {message}\n")
        self.chat_display.configure(state='disabled')
        self.chat_display.see(tk.END)

    def process_message_queue(self):
        """Checks the message queue and displays any messages (runs on main thread)."""
        try:
            while True:
                sender, message = self.message_queue.get_nowait()
                print(f"Processing message from queue for display: {sender}: {message}")
                self.display_message(sender, message)
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_message_queue)


    def send_msg(self, event=None):
        msg_content = self.msg_entry.get()
        if msg_content:
            message_data = create_signed_message(msg_content, MY_NAME)

            message_id = message_data.get('message_id')
            if message_id is not None:
                 seen_message_ids.add(message_id)
                 print(f"Added sent message ID {message_id} to seen.")
            else:
                 print("Warning: Sent message does not have a message ID.")


            self.message_queue.put(("Me", msg_content))
            print(f"Queued own message for display: Me: {msg_content}")

            current_peers = list(peers.keys())
            print(f"My peers list before sending message: {current_peers}")

            for peer_addr in current_peers:
                try:
                    print(f"Attempting to send message to {peer_addr}")
                    send_data_to_peer(peer_addr, message_data)
                    print(f"Successfully sent message ID {message_id} to {peer_addr}")
                except Exception as e:
                    print(f"Failed to send message to {peer_addr}: {e}")
                    # --- MODIFIED: Move to unreachable_peers on send failure ---
                    if peer_addr in peers:
                        print(f"Moving peer {peer_addr} from reachable to unreachable.")
                        # Safely get public key before removing
                        pub_key = peers[peer_addr]
                        unreachable_peers[peer_addr] = pub_key # Add to unreachable
                        del peers[peer_addr] # Remove from peers
                        print(f"Current reachable peers count: {len(peers)}. Unreachable peers count: {len(unreachable_peers)}")


            self.msg_entry.delete(0, tk.END)


# --- Asymmetric Key Functions ---
def generate_rsa_key_pair():
    """Generates a new RSA public and private key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    public_key_serialized = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key_serialized

def get_public_key_from_serialized(public_key_bytes):
    """Deserializes a public key from bytes."""
    return serialization.load_pem_public_key(public_key_bytes)

def sign_message(private_key, message):
    """Signs a message using the sender's private key."""
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_bytes, message, signature_b64):
    """Verifies a message signature using the sender's public key."""
    public_key = get_public_key_from_serialized(public_key_bytes)
    signature = base64.b64decode(signature_b64.encode('utf-8'))

    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature verification successful.")
        return True
    except InvalidSignature:
        print("Signature verification FAILED: InvalidSignature.")
        return False
    except Exception as e:
        print(f"Error during signature verification: {e}")
        return False


def create_signed_message(message_content, sender_name):
    """Creates the full chat message dictionary with content, sender, signature, ID, and public key."""
    global MY_PRIVATE_KEY, MY_PUBLIC_KEY_SERIALIZED, MY_PORT

    core_message_data = {'from': sender_name, 'message': message_content}
    core_message_json = json.dumps(core_message_data)

    signature = sign_message(MY_PRIVATE_KEY, core_message_json)

    encrypted_message = symmetric_cipher.encrypt(core_message_json.encode())

    full_data = {
        'type': 'chat_message',
        'message_id': str(uuid.uuid4()),
        'encrypted_msg': base64.b64encode(encrypted_message).decode('utf-8'),
        'signature': signature,
        'sender_pub_key': MY_PUBLIC_KEY_SERIALIZED.decode('utf-8'),
        'listening_port': MY_PORT
    }

    return full_data


# --- New function to create a peer list message ---
def create_peer_list_message():
    global peers, unreachable_peers, MY_PORT, MY_NAME, MY_PUBLIC_KEY_SERIALIZED
    """Creates a message containing this peer's known peer list (reachable + unreachable) to share."""
    peer_list_data = {
        'type': 'peer_list',
        'from': MY_NAME,
        'sender_pub_key': MY_PUBLIC_KEY_SERIALIZED.decode('utf-8'),
        'listening_port': MY_PORT,
        'peers': {} # Dictionary to hold peers: {peer_address_str: pub_key_str}
    }
    # Combine reachable and unreachable peers to share a broader view of the network
    combined_peers = dict(peers) # Start with reachable
    combined_peers.update(unreachable_peers) # Add unreachable (will overwrite if same peer somehow in both)

    for addr, pub_key in combined_peers.items():
        # Ensure we don't include our own address in the list sent to others
        if addr != (socket.gethostbyname(socket.gethostname()), MY_PORT):
            peer_list_data['peers'][f"{addr[0]}:{addr[1]}"] = pub_key


    print(f"Created peer list message (contains {len(peer_list_data['peers'])} peers) to share.")
    return peer_list_data


# --- Network Functions ---
def send_data_to_peer(peer_addr, data):
    """Sends data (dictionary) to a specific peer's listening address."""
    if isinstance(peer_addr, str):
         try:
              ip_str, port_str = peer_addr.split(':')
              peer_addr = (ip_str, int(port_str))
         except Exception as e:
              print(f"Invalid peer address string format: {peer_addr}. Error: {e}")
              raise ValueError("Invalid peer address format") from e # Raise a specific error

    if peer_addr == (socket.gethostbyname(socket.gethostname()), MY_PORT):
         # print(f"Attempted to send data to self at {peer_addr}. Skipping.") # Less critical debug
         return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        try:
             s.connect(peer_addr)
             s.sendall(json.dumps(data).encode())
             # Success print is done by the caller (send_msg or re-broadcast logic)
             # print(f"Successfully sent data to {peer_addr}") # Moved print to caller
        except Exception as e:
             # Failure print is done by the caller
             # print(f"Failed to send data to {peer_addr}: {e}") # Moved print to caller
             raise # Re-raise the exception to be caught by the caller


# handle_client processes a single incoming connection and message
def handle_client(conn, addr, gui):
    global peers, seen_message_ids, unreachable_peers
    print(f"Handling new incoming connection from {addr}")

    try:
        conn.settimeout(10)
        data_bytes = conn.recv(4096)
        if not data_bytes:
            print(f"Connection from {addr} closed immediately or no data.")
            return

        try:
            data = json.loads(data_bytes.decode())
            # print(f"Received raw data from {addr}: {data}") # Optional: print full received data
        except json.JSONDecodeError:
            print(f"Failed to decode JSON from {addr}. Skipping message.")
            return

        # --- Extract common message fields ---
        message_type = data.get('type')
        message_id = data.get('message_id')
        sender_pub_key_string = data.get('sender_pub_key')
        sender_listening_port = data.get('listening_port')
        sender_name = data.get('from', 'Unknown')

        print(f"Received message details: ID={message_id}, Type={message_type}, From={sender_name}, Listening Port={sender_listening_port}, Connecting Addr={addr}")

        # Determine the peer's listening address for storage and comparison
        peer_listening_addr = None
        if sender_listening_port:
            peer_listening_addr = (addr[0], sender_listening_port)

            # --- MODIFIED: When receiving a message from an unreachable peer, move them back to reachable ---
            if peer_listening_addr in unreachable_peers:
                print(f"Received message from {peer_listening_addr}, moving back to reachable peers.")
                peers[peer_listening_addr] = unreachable_peers.pop(peer_listening_addr) # Move from unreachable to peers
                print(f"Current reachable peers count: {len(peers)}. Unreachable peers count: {len(unreachable_peers)}")
                # Optional: Trigger a peer list exchange upon reconnection
                # This is handled by the bootstrap response logic below


            # Store or update the peer's information using their *listening address* as the key
            # If the peer is in unreachable, this will update their key there.
            # If the peer is in reachable, this will update their key there.
            # If the peer is new, this will add them to reachable.
            if sender_pub_key_string:
                 # Prioritize adding to reachable if they just sent a message
                 peers[peer_listening_addr] = sender_pub_key_string
                 # If they were in unreachable, remove them from there now that they've sent something
                 if peer_listening_addr in unreachable_peers:
                      del unreachable_peers[peer_listening_addr]
                      print(f"Moved peer {peer_listening_addr} from unreachable to reachable based on incoming message.")

                 print(f"Added/Updated peer {peer_listening_addr} with public key. Current reachable peers count: {len(peers)}. Unreachable count: {len(unreachable_peers)}")

            else:
                 print(f"Warning: Received data from {addr} with listening_port but without sender_pub_key. Cannot fully manage peer.")
        else:
             print(f"Received data from {addr} without listening_port. Cannot add/update peer for sending.")


        # --- Handle different message types ---

        # --- Handle Chat Messages ---
        if message_type == 'chat_message':
            # Deduplication check first for chat messages
            if message_id is not None and message_id in seen_message_ids:
                print(f"Received duplicate chat message with ID {message_id} from {addr}. Skipping processing.")
                return

            # If it's a new chat message (or no ID), add its ID to the seen set
            if message_id is not None:
                 seen_message_ids.add(message_id)
                 print(f"Added new chat message ID {message_id} to seen.")
            else:
                 print("Received chat message without a message ID. Cannot deduplicate.")


            encrypted_msg_b64 = data.get('encrypted_msg')
            signature_b64 = data.get('signature')

            pub_key_to_verify_with = peers.get(peer_listening_addr) # Get public key from reachable peers


            if encrypted_msg_b64 and signature_b64 and pub_key_to_verify_with:
                print(f"Processing chat message with ID {message_id} from {sender_name} ({peer_listening_addr}) for verification.")
                try:
                    encrypted_msg = base64.b64decode(encrypted_msg_b64.encode('utf-8'))
                    decrypted_core_message_json = symmetric_cipher.decrypt(encrypted_msg).decode()

                    if verify_signature(pub_key_to_verify_with.encode('utf-8'), decrypted_core_message_json, signature_b64):
                        core_message_data = json.loads(decrypted_core_message_json)
                        actual_sender_name = core_message_data.get('from', 'Unknown')
                        message_content = core_message_data.get('message')

                        print(f"Signature valid. Queueing chat message ID {message_id} for display from {actual_sender_name}.")
                        gui.message_queue.put((actual_sender_name, message_content))

                        # --- Re-broadcast to other known peers ---
                        # Only re-broadcast chat messages.
                        # Re-broadcast to all *reachable* peers except the sender.
                        print(f"My reachable peers list before re-broadcasting message ID {message_id} from {actual_sender_name}: {list(peers.keys())}")

                        # Iterate over a copy of keys
                        for peer_addr_to_send in list(peers.keys()):
                             # Ensure we don't send the message back to the sender (using their listening address)
                             if peer_listening_addr and peer_addr_to_send != peer_listening_addr:
                                 # Ensure we don't re-broadcast to ourselves
                                 if peer_addr_to_send != (socket.gethostbyname(socket.gethostname()), MY_PORT):
                                     try:
                                          print(f"Attempting to re-broadcast message ID {message_id} to {peer_addr_to_send}")
                                          send_data_to_peer(peer_addr_to_send, data) # Send the original received data
                                          print(f"Successfully re-broadcasted message ID {message_id} to {peer_addr_to_send}")
                                     except Exception as e:
                                          print(f"Failed to re-broadcast message ID {message_id} to {peer_addr_to_send}: {e}")
                                          # --- MODIFIED: Move to unreachable_peers on re-broadcast failure ---
                                          if peer_addr_to_send in peers:
                                              print(f"Moving peer {peer_addr_to_send} from reachable to unreachable.")
                                              # Safely get public key before removing
                                              pub_key = peers[peer_addr_to_send]
                                              unreachable_peers[peer_addr_to_send] = pub_key
                                              del peers[peer_addr_to_send]
                                              print(f"Current reachable peers count: {len(peers)}. Unreachable peers count: {len(unreachable_peers)}")


                    else:
                        print(f"Signature verification failed for chat message with ID {message_id} from {sender_name}. Message discarded.")

                except InvalidSignature:
                    print(f"Signature verification failed during crypto op for chat message with ID {message_id} from {sender_name}. Message discarded.")
                except Exception as e:
                    print(f"Error processing chat message with ID {message_id} from {sender_name}: {e}")
            else:
                 print(f"Received incomplete chat message from {sender_name}. Missing encrypted_msg, signature, or sender_pub_key/listening_port.")


        # --- Handle Bootstrap Messages ---
        elif message_type == 'bootstrap':
             print(f"Processed bootstrap message from {sender_name} ({peer_listening_addr}).")
             # Peer is already added/updated in the peers dictionary at the start of handle_client if info was present.
             # If this peer was in unreachable, they are now moved back to reachable.

             if data.get('message'):
                 gui.message_queue.put((sender_name, data['message']))
                 print(f"Queueing bootstrap join message for display from {sender_name}.")

             # --- Active Peer Discovery: Send our peer list back to the newly bootstrapped peer ---
             # We send our list of known peers (reachable + unreachable) to the peer who just connected to us.
             # Sending both gives the bootstrapping peer more potential contacts.
             if peer_listening_addr and peer_listening_addr != (socket.gethostbyname(socket.gethostname()), MY_PORT):
                 try:
                     print(f"Attempting to send peer list to newly bootstrapped peer {peer_listening_addr}")
                     peer_list_message = create_peer_list_message() # Create message with our current peers (both reachable and unreachable)
                     # Send this peer list back to the peer who just bootstrapped to us using their reported listening address.
                     send_data_to_peer(peer_listening_addr, peer_list_message)
                     print(f"Successfully sent peer list to {peer_listening_addr} (contained {len(peer_list_message['peers'])} peers).")
                 except Exception as e:
                     print(f"Failed to send peer list to {peer_listening_addr}: {e}")


        # --- Handle Received Peer List Messages ---
        elif message_type == 'peer_list':
             print(f"Received peer list message from {sender_name} ({peer_listening_addr}).")
             received_peers_dict = data.get('peers', {})
             print(f"Received peers in list: {received_peers_dict}")

             # Add peers from the received list to our own local peers dictionary (either reachable or unreachable).
             for peer_addr_str, pub_key_str in received_peers_dict.items():
                 try:
                     ip_str, port_str = peer_addr_str.split(':')
                     peer_addr_tuple = (ip_str, int(port_str))

                     # Only add if it's not our own address
                     if peer_addr_tuple != (socket.gethostbyname(socket.gethostname()), MY_PORT):
                          # If we don't have this peer in either reachable or unreachable, add it to unreachable initially.
                          # If they are already known (in peers or unreachable), we keep their existing status,
                          # but update their key if a new one is provided.
                          if peer_addr_tuple not in peers and peer_addr_tuple not in unreachable_peers:
                               unreachable_peers[peer_addr_tuple] = pub_key_str # Add as unreachable initially
                               print(f"Added new peer from received list to unreachable: {peer_addr_tuple}")
                          elif peer_addr_tuple in peers:
                               # If already reachable, update their key if different (optional)
                               if peers[peer_addr_tuple] != pub_key_str:
                                   peers[peer_addr_tuple] = pub_key_str
                                   print(f"Updated public key for reachable peer {peer_addr_tuple} from received list.")
                          elif peer_addr_tuple in unreachable_peers:
                               # If already unreachable, update their key if different (optional)
                               if unreachable_peers[peer_addr_tuple] != pub_key_str:
                                    unreachable_peers[peer_addr_tuple] = pub_key_str
                                    print(f"Updated public key for unreachable peer {peer_addr_tuple} from received list.")


                 except Exception as e:
                     print(f"Error processing peer address '{peer_addr_str}' from received list. Error: {e}")
             print(f"Finished processing received peer list. Reachable count: {len(peers)}. Unreachable count: {len(unreachable_peers)}.")


        # --- Handle Unknown Message Types ---
        else:
            print(f"Received unknown message type '{message_type}' from {sender_name} ({peer_listening_addr}). Skipping.")


    except socket.timeout:
        print(f"Timeout receiving data from {addr}.")
    except Exception as e:
        print(f"Error handling connection from {addr}: {e}")
    finally:
        print(f"Connection from {addr} handled and closed.")
        conn.close()


# start_server continuously accepts new incoming connections
def start_server(gui):
    global MY_PORT
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', MY_PORT))
        server.listen(5)
        print(f"Server listening on port {MY_PORT}")

        while True:
            try:
                conn, addr = server.accept()
                threading.Thread(target=handle_client, args=(conn, addr, gui), daemon=True).start()
            except Exception as e:
                print(f"Error in server accept loop: {e}")
                # Consider adding a small sleep here to prevent a tight loop if accept continuously fails
                # time.sleep(1) # Optional: uncomment to sleep on error
                # break # Uncomment to stop the server loop on the first error.
    except Exception as e:
         print(f"Failed to bind server to port {MY_PORT}: {e}")
    finally:
         server.close()
         print(f"Server on port {MY_PORT} stopped.")


# --- Bootstrap Function ---
# This function attempts to connect to a bootstrap peer. It should be defined before run_chat_app.
def bootstrap(host, port):
    """Attempts to connect to a bootstrap peer and send initial info."""
    global MY_PUBLIC_KEY_SERIALIZED, MY_PORT, MY_NAME
    bootstrap_addr = (host, port)
    print(f"Attempting to bootstrap to {bootstrap_addr}")
    try:
        # Prepare the initial bootstrap message to send to the bootstrap peer.
        bootstrap_message_data = {
             'type': 'bootstrap',
             'from': MY_NAME,
             'sender_pub_key': MY_PUBLIC_KEY_SERIALIZED.decode('utf-8'),
             'listening_port': MY_PORT, # Include our listening port
             'message': f"{MY_NAME} joined the chat" # Initial unencrypted message
        }
        # Send the bootstrap message. send_data_to_peer creates a new connection.
        # After sending this, the bootstrap peer (if using the latest code) should send its peer list back to our server.
        send_data_to_peer(bootstrap_addr, bootstrap_message_data)
        print(f"Bootstrap message sent to {bootstrap_addr}. Peer list response expected shortly.")

    except Exception as e:
        print(f"Bootstrap failed to {bootstrap_addr}: {e}")



# --- Periodic Reconnection Task (Point 4) ---
# This function attempts to reconnect to unreachable peers. It should be defined before run_chat_app.
def attempt_reconnections():
    global unreachable_peers, peers
    print(f"Attempting reconnections to {len(unreachable_peers)} unreachable peers.")

    # Create a list of unreachable peers to iterate over, as the dictionary might be modified
    peers_to_try = list(unreachable_peers.keys())

    # Limit the number of reconnection attempts per cycle if the unreachable list is large
    # For a small network, trying all is fine. For larger, sample randomly.
    # num_to_try = min(len(peers_to_try), 5) # Example: try max 5 per cycle
    # peers_to_try = random.sample(peers_to_try, num_to_try) # Example: random sample

    for peer_addr in peers_to_try:
        # Only attempt reconnection if the peer is still in the unreachable list
        # (Could have become reachable via another incoming message since the list was made)
        if peer_addr in unreachable_peers and peer_addr not in peers:
            try:
                print(f"Attempting bootstrap reconnection to {peer_addr}")
                # We use the existing bootstrap function to try and reconnect.
                # If successful, the other peer's handle_client will receive the bootstrap,
                # add us back to their peers, and send their peer list back to us.
                # Our handle_client will then receive their bootstrap response and peer list,
                # moving the peer back from unreachable_peers to peers.
                bootstrap(peer_addr[0], peer_addr[1])
                # Note: The success/failure message is printed inside the bootstrap and send_data_to_peer functions.
                # If send_data_to_peer raises an exception, it's caught here.
            except Exception as e:
                print(f"Reconnection attempt to {peer_addr} failed: {e}")
                # The peer remains in unreachable_peers until a bootstrap attempt succeeds and
                # a message is successfully received from them by handle_client.


    # Schedule the next reconnection attempt
    reconnection_interval = 60 # Attempt reconnections every 60 seconds
    # --- FIX: Use the correct way to set daemon for compatibility ---
    reconnection_timer = threading.Timer(reconnection_interval, attempt_reconnections)
    reconnection_timer.daemon = True # Set daemon attribute after creation
    reconnection_timer.start() # Start the timer


# --- Launch GUI and Networking ---
# This function sets up the GUI, starts the server, and initiates bootstrap/reconnection timers.
# It should be the last major function defined before the entry point.
def run_chat_app():
    global MY_PORT, MY_NAME, MY_PRIVATE_KEY, MY_PUBLIC_KEY_SERIALIZED

    MY_PORT = int(input("Enter your port: "))
    MY_NAME = input("Enter your name: ")
    bootstrap_ip = input("Enter bootstrap IP (leave blank if none): ")
    bootstrap_port = input("Enter bootstrap port (leave blank if none): ")

    print("Generating RSA key pair...")
    MY_PRIVATE_KEY, MY_PUBLIC_KEY_SERIALIZED = generate_rsa_key_pair()
    print("Keys generated.")

    root = tk.Tk()
    gui = ChatGUI(root)

    # Start the network server thread. This thread listens for incoming connections.
    # daemon=True ensures the program can exit even if this thread is still running.
    threading.Thread(target=start_server, args=(gui,), daemon=True).start()

    # The initial cleanup timer for seen_message_ids is started at the module level.

    # Attempt to bootstrap if configured after a short delay to let the server start.
    if bootstrap_ip and bootstrap_port:
        try:
            bootstrap_port_int = int(bootstrap_port)
            # --- FIX: Use the correct way to set daemon for compatibility for the initial bootstrap timer ---
            initial_bootstrap_timer_obj = threading.Timer(1, bootstrap, args=(bootstrap_ip, bootstrap_port_int))
            initial_bootstrap_timer_obj.daemon = True # Set daemon attribute after creation
            initial_bootstrap_timer_obj.start() # Start the timer
        except ValueError:
            print(f"Invalid bootstrap port entered: {bootstrap_port}. Bootstrap skipped.")


    # --- Start the periodic reconnection task after a delay ---
    # This timer periodically calls the attempt_reconnections function.
    initial_reconnection_delay = 10 # Start attempting reconnections 10 seconds after launch

    # --- FIX: Use the correct way to set daemon for compatibility for the initial reconnection timer ---
    # Create the Timer object first, then set its daemon attribute, then start it.
    reconnection_timer_obj = threading.Timer(initial_reconnection_delay, attempt_reconnections)
    reconnection_timer_obj.daemon = True # Set daemon attribute after creation
    reconnection_timer_obj.start() # Start the timer


    # The GUI event loop must run on the main thread.
    # root.mainloop() is a blocking call that keeps the GUI window open and responsive.
    root.mainloop()

# --- Entry Point ---
# This block is executed only when the script is run directly.

if __name__ == "__main__":
    # Check if required libraries are installed before starting the application.
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.asymmetric import rsa
        import base64
        import queue
        import time
        import uuid
        import socket
        import threading
        import json
        import tkinter
        from tkinter import scrolledtext
        import random
    except ImportError as e:
        print(f"Error: Required library not found: {e.name}")
        print("Please install the 'cryptography' library using: pip install cryptography")
        # uuid, socket, threading, json, tkinter, queue, random are standard libraries and should be available.
        exit()

    # Run the main chat application function to start everything.
    run_chat_app()