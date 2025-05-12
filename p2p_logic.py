import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox
import threading
import socket
import json
import time
import uuid
import rsa
import base64
import sys
import argparse
from typing import Dict, List, Tuple, Set, Optional
import logging


# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('p2p_chat')


class Peer:
    def __init__(self, host: str, port: int, bootstrap_nodes: List[Tuple[str, int]] = None):
        """Initialize a peer in the P2P network.

        Args:
            host: Host address of this peer
            port: Port number this peer listens on
            bootstrap_nodes: List of known peers to connect to initially
        """
        self.host = host
        self.port = port
        self.addr = (host, port)
        self.id = str(uuid.uuid4())[:8]  # Short unique ID
        self.username = f"user_{self.id}"

        # Socket for incoming connections
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(self.addr)

        # Known peers in the network: {peer_id: (host, port)}
        self.peers = {}

        # Active connections: {peer_id: socket}
        self.connections = {}

        # Active group chats: {group_name: set(peer_ids)}
        self.groups = {}

        # Messages seen to avoid duplicates (for gossip protocol)
        self.message_cache = set()

        # Message history: {chat_id: [messages]}
        # chat_id can be peer_id for direct messages or group_name for group chats
        self.message_history = {}

        # Generate RSA key pair for encryption
        self.public_key, self.private_key = rsa.newkeys(2048)

        # Store public keys of other peers: {peer_id: public_key}
        self.peer_public_keys = {}

        # Bootstrap nodes to connect to
        self.bootstrap_nodes = bootstrap_nodes or []

        # Run flag to control threads
        self.running = True

        # UI callbacks
        self.on_message_received = None
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self.on_group_created = None

    def start(self):
        """Start the peer server and connect to the network."""
        logger.info(f"Starting peer {self.id} at {self.host}:{self.port}")

        # Start server to listen for incoming connections
        self.server_socket.listen(10)
        server_thread = threading.Thread(target=self.listen_for_connections)
        server_thread.daemon = True
        server_thread.start()

        # Connect to bootstrap nodes
        if self.bootstrap_nodes:
            for node in self.bootstrap_nodes:
                self.connect_to_peer(node[0], node[1])

    def listen_for_connections(self):
        """Listen for incoming connection requests from other peers."""
        logger.info(f"Listening for connections on {self.host}:{self.port}")

        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"New connection from {client_address}")

                # Start a new thread to handle this connection
                handler = threading.Thread(target=self.handle_connection, args=(client_socket,))
                handler.daemon = True
                handler.start()
            except Exception as e:
                if self.running:  # Only log if we're supposed to be running
                    logger.error(f"Error accepting connection: {e}")

    def handle_connection(self, client_socket):
        """Handle communication with a connected peer."""
        peer_id = None

        try:
            # First message should be the peer's info
            data = client_socket.recv(4096)
            if not data:
                return

            message = json.loads(data.decode('utf-8'))

            if message['type'] == 'hello':
                peer_id = message['peer_id']
                peer_host = message['host']
                peer_port = message['port']
                peer_username = message.get('username', f"user_{peer_id}")
                peer_key = rsa.PublicKey.load_pkcs1(base64.b64decode(message['public_key']))

                # Store peer information
                self.peers[peer_id] = (peer_host, peer_port)
                self.connections[peer_id] = client_socket
                self.peer_public_keys[peer_id] = peer_key

                logger.info(f"Connected to peer {peer_username} ({peer_id})")

                # Send our own information
                self.send_hello(client_socket)

                # Send known peers for discovery
                if len(self.peers) > 1:  # If we know other peers
                    self.send_peer_list(peer_id)

                # Notify UI
                if self.on_peer_connected:
                    self.on_peer_connected(peer_id, peer_username)

                # Main message loop for this connection
                while self.running:
                    try:
                        data = client_socket.recv(4096)
                        if not data:
                            break

                        message = json.loads(data.decode('utf-8'))
                        self.process_message(message, peer_id)
                    except json.JSONDecodeError:
                        logger.error(f"Invalid JSON received from {peer_id}")
                    except Exception as e:
                        logger.error(f"Error processing message from {peer_id}: {e}")
                        break

        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            # Clean up connection
            if peer_id and peer_id in self.connections:
                client_socket.close()
                del self.connections[peer_id]
                logger.info(f"Connection with peer {peer_id} closed")
                
                # Notify UI
                if self.on_peer_disconnected:
                    self.on_peer_disconnected(peer_id)

    def connect_to_peer(self, host, port):
        """Establish connection to another peer."""
        if (host, port) == (self.host, self.port):
            return False  # Don't connect to self

        # Check if we're already connected to this address
        for peer_id, addr in self.peers.items():
            if addr == (host, port):
                logger.info(f"Already connected to {host}:{port}")
                return False

        try:
            # Create socket and connect
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))

            # Send hello message with our information
            self.send_hello(sock)

            # Wait for response
            data = sock.recv(4096)
            if not data:
                sock.close()
                return False

            message = json.loads(data.decode('utf-8'))

            if message['type'] == 'hello':
                peer_id = message['peer_id']
                peer_username = message.get('username', peer_id)
                peer_key = rsa.PublicKey.load_pkcs1(base64.b64decode(message['public_key']))

                # Store peer information
                self.peers[peer_id] = (host, port)
                self.connections[peer_id] = sock
                self.peer_public_keys[peer_id] = peer_key

                logger.info(f"Connected to peer {message.get('username', peer_id)}")

                # Notify UI
                if self.on_peer_connected:
                    self.on_peer_connected(peer_id, peer_username)

                # Start thread to listen for messages from this peer
                handler = threading.Thread(target=self.handle_peer_messages, args=(sock, peer_id))
                handler.daemon = True
                handler.start()

                return True
        except Exception as e:
            logger.error(f"Failed to connect to {host}:{port}: {e}")
            return False

    def handle_peer_messages(self, sock, peer_id):
        """Handle incoming messages from an established peer connection."""
        try:
            while self.running:
                data = sock.recv(4096)
                if not data:
                    break

                message = json.loads(data.decode('utf-8'))
                self.process_message(message, peer_id)

        except Exception as e:
            logger.error(f"Error handling messages from {peer_id}: {e}")
        finally:
            # Clean up connection
            if peer_id in self.connections:
                sock.close()
                del self.connections[peer_id]
                logger.info(f"Connection with peer {peer_id} closed")
                
                # Notify UI
                if self.on_peer_disconnected:
                    self.on_peer_disconnected(peer_id)

    def process_message(self, message, sender_id):
        """Process received messages based on their type."""
        msg_type = message.get('type')

        if msg_type == 'text':
            # Private message
            if message['message_id'] not in self.message_cache:
                self.message_cache.add(message['message_id'])

                if message.get('encrypted', False):
                    try:
                        # Decrypt message if it's for us
                        if message['to'] == self.id:
                            encrypted_msg = base64.b64decode(message['content'])
                            content = rsa.decrypt(encrypted_msg, self.private_key).decode('utf-8')
                            
                            # Store in message history
                            chat_id = message['from']
                            if chat_id not in self.message_history:
                                self.message_history[chat_id] = []
                            
                            self.message_history[chat_id].append({
                                'from': message['from'],
                                'from_username': message['from_username'],
                                'content': content,
                                'timestamp': message['timestamp'],
                                'encrypted': True
                            })
                            
                            # Notify UI
                            if self.on_message_received:
                                self.on_message_received(chat_id, message['from_username'], content, True)
                    except Exception as e:
                        logger.error(f"Failed to decrypt message: {e}")
                else:
                    # Public message
                    chat_id = 'broadcast'
                    if chat_id not in self.message_history:
                        self.message_history[chat_id] = []
                    
                    self.message_history[chat_id].append({
                        'from': message['from'],
                        'from_username': message['from_username'],
                        'content': message['content'],
                        'timestamp': message['timestamp'],
                        'encrypted': False
                    })
                    
                    # Notify UI
                    if self.on_message_received:
                        self.on_message_received(chat_id, message['from_username'], message['content'], False)

                # Forward message (gossip protocol)
                self.forward_message(message, sender_id)

        elif msg_type == 'group':
            # Group message
            if message['message_id'] not in self.message_cache:
                self.message_cache.add(message['message_id'])

                group_name = message['group']
                if group_name in self.groups:
                    if message.get('encrypted', False):
                        try:
                            # Try to decrypt if we're in the group
                            encrypted_msg = base64.b64decode(message['content'])
                            content = rsa.decrypt(encrypted_msg, self.private_key).decode('utf-8')
                            
                            # Store in message history
                            if group_name not in self.message_history:
                                self.message_history[group_name] = []
                            
                            self.message_history[group_name].append({
                                'from': message['from'],
                                'from_username': message['from_username'],
                                'content': content,
                                'timestamp': message['timestamp'],
                                'group': group_name,
                                'encrypted': True
                            })
                            
                            # Notify UI
                            if self.on_message_received:
                                self.on_message_received(group_name, message['from_username'], content, True, is_group=True)
                        except Exception:
                            # Not for us to decrypt
                            pass
                    else:
                        # Store in message history
                        if group_name not in self.message_history:
                            self.message_history[group_name] = []
                        
                        self.message_history[group_name].append({
                            'from': message['from'],
                            'from_username': message['from_username'],
                            'content': message['content'],
                            'timestamp': message['timestamp'],
                            'group': group_name,
                            'encrypted': False
                        })
                        
                        # Notify UI
                        if self.on_message_received:
                            self.on_message_received(group_name, message['from_username'], message['content'], False, is_group=True)

                    # Forward to other group members (gossip protocol)
                    self.forward_message(message, sender_id)

        elif msg_type == 'peer_list':
            # Handle peer discovery
            new_peers = message.get('peers', {})
            for peer_id, info in new_peers.items():
                if peer_id != self.id and peer_id not in self.peers:
                    host, port = info['addr']
                    logger.info(f"Discovered new peer: {peer_id} at {host}:{port}")
                    # Try to connect to the new peer
                    threading.Thread(target=self.connect_to_peer, args=(host, port)).start()

        elif msg_type == 'create_group':
            # Handle group creation
            group_name = message['group_name']
            members = set(message['members'])

            if self.id in members:
                self.groups[group_name] = members
                logger.info(f"Joined group: {group_name}")
                
                # Notify UI
                if self.on_group_created:
                    self.on_group_created(group_name, list(members))

            # Forward group creation (gossip protocol)
            if message['message_id'] not in self.message_cache:
                self.message_cache.add(message['message_id'])
                self.forward_message(message, sender_id)

    def send_hello(self, sock):
        """Send initial hello message with peer information."""
        hello = {
            'type': 'hello',
            'peer_id': self.id,
            'username': self.username,
            'host': self.host,
            'port': self.port,
            'public_key': base64.b64encode(self.public_key.save_pkcs1()).decode('utf-8')
        }
        sock.sendall(json.dumps(hello).encode('utf-8'))

    def send_peer_list(self, peer_id):
        """Send list of known peers to a specific peer."""
        peer_info = {}
        for pid, addr in self.peers.items():
            if pid != peer_id and pid != self.id:
                peer_info[pid] = {'addr': addr}

        message = {
            'type': 'peer_list',
            'peers': peer_info
        }

        if peer_id in self.connections:
            try:
                self.connections[peer_id].sendall(json.dumps(message).encode('utf-8'))
            except Exception as e:
                logger.error(f"Failed to send peer list to {peer_id}: {e}")

    def send_message(self, content, to_peer=None, group=None):
        """Send a message to a specific peer or group."""
        message_id = str(uuid.uuid4())

        if group:
            # Group message
            if group not in self.groups:
                return False

            message = {
                'type': 'group',
                'message_id': message_id,
                'from': self.id,
                'from_username': self.username,
                'group': group,
                'content': content,
                'timestamp': time.time(),
                'encrypted': False
            }

            # Store in message history
            if group not in self.message_history:
                self.message_history[group] = []
            
            self.message_history[group].append({
                'from': self.id,
                'from_username': self.username,
                'content': content,
                'timestamp': time.time(),
                'group': group,
                'encrypted': False
            })

        else:
            # Direct message
            if to_peer:
                if to_peer not in self.peers:
                    return False

                # Encrypt message if we have the public key
                encrypted = False
                encrypted_content = content
                if to_peer in self.peer_public_keys:
                    try:
                        encrypted_bytes = rsa.encrypt(content.encode('utf-8'), self.peer_public_keys[to_peer])
                        encrypted_content = base64.b64encode(encrypted_bytes).decode('utf-8')
                        encrypted = True
                    except Exception as e:
                        logger.error(f"Failed to encrypt message: {e}")
                        return False

                message = {
                    'type': 'text',
                    'message_id': message_id,
                    'from': self.id,
                    'from_username': self.username,
                    'to': to_peer,
                    'content': encrypted_content,
                    'timestamp': time.time(),
                    'encrypted': encrypted
                }
                
                # Store in message history
                if to_peer not in self.message_history:
                    self.message_history[to_peer] = []
                
                self.message_history[to_peer].append({
                    'from': self.id,
                    'from_username': self.username,
                    'to': to_peer,
                    'content': content,  # Store original content
                    'timestamp': time.time(),
                    'encrypted': encrypted
                })
            else:
                # Broadcast message
                message = {
                    'type': 'text',
                    'message_id': message_id,
                    'from': self.id,
                    'from_username': self.username,
                    'content': content,
                    'timestamp': time.time(),
                    'encrypted': False
                }
                
                # Store in message history
                chat_id = 'broadcast'
                if chat_id not in self.message_history:
                    self.message_history[chat_id] = []
                
                self.message_history[chat_id].append({
                    'from': self.id,
                    'from_username': self.username,
                    'content': content,
                    'timestamp': time.time(),
                    'encrypted': False
                })

        # Add to our message cache to avoid processing our own messages again
        self.message_cache.add(message_id)

        # Send to all connected peers (gossip protocol)
        self.broadcast_message(message)
        return True

    def broadcast_message(self, message):
        """Send a message to all connected peers."""
        message_json = json.dumps(message)
        message_bytes = message_json.encode('utf-8')

        failed_peers = []

        for peer_id, sock in list(self.connections.items()):
            try:
                sock.sendall(message_bytes)
            except Exception as e:
                logger.error(f"Failed to send message to {peer_id}: {e}")
                failed_peers.append(peer_id)

        # Clean up failed connections
        for peer_id in failed_peers:
            if peer_id in self.connections:
                self.connections[peer_id].close()
                del self.connections[peer_id]
                logger.info(f"Removed failed connection to {peer_id}")
                
                # Notify UI
                if self.on_peer_disconnected:
                    self.on_peer_disconnected(peer_id)

    def forward_message(self, message, sender_id):
        """Forward a message to all peers except the sender (part of gossip protocol)."""
        message_json = json.dumps(message)
        message_bytes = message_json.encode('utf-8')

        for peer_id, sock in list(self.connections.items()):
            if peer_id != sender_id:  # Don't send back to the sender
                try:
                    sock.sendall(message_bytes)
                except Exception:
                    # Connection might have failed, will be cleaned up elsewhere
                    continue

    def create_group(self, group_name, members):
        """Create a new group chat."""
        if not members:
            return False

        # Add ourselves to the group
        member_set = set(members)
        member_set.add(self.id)

        # Store group locally
        self.groups[group_name] = member_set

        # Send group creation message
        message = {
            'type': 'create_group',
            'message_id': str(uuid.uuid4()),
            'group_name': group_name,
            'members': list(member_set),
            'created_by': self.id,
            'timestamp': time.time()
        }

        # Add to message cache
        self.message_cache.add(message['message_id'])

        # Broadcast group creation
        self.broadcast_message(message)
        
        # Notify UI
        if self.on_group_created:
            self.on_group_created(group_name, list(member_set))
        
        return True

    def set_username(self, username):
        """Set the display name for this peer."""
        self.username = username
        return True

    def shutdown(self):
        """Clean shutdown of the peer."""
        self.running = False

        # Close all connections
        for sock in self.connections.values():
            try:
                sock.close()
            except:
                pass

        # Close server socket
        try:
            self.server_socket.close()
        except:
            pass

        logger.info("Peer shutdown complete")

