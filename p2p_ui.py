import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox, Text, font
import time
import sys
import argparse

from p2p_logic import Peer


class ChatUI:
    def __init__(self, root, peer):
        """Initialize the Chat UI with a reference to the peer."""
        self.root = root
        self.peer = peer
        self.current_chat = "broadcast"  # Default to broadcast
        self.chats = {"broadcast": []}  # Store message history
        self.peers_list = []  # Store connected peers
        self.groups = {}  # Store group information
        
        # Set up callbacks
        self.peer.on_message_received = self.handle_message_received
        self.peer.on_peer_connected = self.handle_peer_connected
        self.peer.on_peer_disconnected = self.handle_peer_disconnected
        self.peer.on_group_created = self.handle_group_created
        
        # Define teal colors
        self.colors = {
            "teal_dark": "#008080",  # Dark teal
            "teal_medium": "#20B2AA",  # Medium teal
            "teal_light": "#E0F2F1",  # Light teal
            "teal_accent": "#00CED1",  # Bright teal accent
            "text_dark": "#333333",
            "text_light": "#FFFFFF",
            "message_sent": "#E3F2FD",
            "message_received": "#E0F2F1",
            "bubble_sent": "#DCF8C6",  # Light green for sent messages
            "bubble_received": "#FFFFFF",  # White for received messages
            "timestamp": "#888888",  # Gray for timestamps
            "system_msg": "#FFE0B2"  # Light orange for system messages
        }
        
        # Style configuration
        self.root.configure(bg=self.colors["teal_light"])
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles with teal theme
        self.configure_styles()
        
        self.root.title(f"P2P Chat - {self.peer.id}")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Main frame
        self.main_frame = ttk.Frame(root, style="Main.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create UI components
        self.create_header()
        self.create_sidebar()
        self.create_chat_area()
        self.create_status_bar()
        
        # Initial refresh of peers list
        self.refresh_sidebar()
        
        # Set up protocol for window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def configure_styles(self):
        """Configure custom styles for the UI components."""
        # Frame styles
        self.style.configure("Main.TFrame", background=self.colors["teal_light"])
        self.style.configure("Header.TFrame", background=self.colors["teal_dark"])
        self.style.configure("Sidebar.TFrame", background=self.colors["teal_light"])
        self.style.configure("Content.TFrame", background=self.colors["teal_light"])
        self.style.configure("Status.TFrame", background=self.colors["teal_dark"])
        
        # Label styles
        self.style.configure("Header.TLabel", 
                             background=self.colors["teal_dark"],
                             foreground=self.colors["text_light"],
                             font=("Arial", 16, "bold"),
                             padding=10)
        
        self.style.configure("Status.TLabel", 
                             background=self.colors["teal_dark"],
                             foreground=self.colors["text_light"],
                             font=("Arial", 10),
                             padding=2)
        
        # Button styles
        self.style.configure("TButton", 
                             background=self.colors["teal_medium"],
                             foreground=self.colors["text_dark"],
                             padding=5,
                             font=("Arial", 10))
        
        self.style.map("TButton",
                       background=[("active", self.colors["teal_accent"])],
                       foreground=[("active", self.colors["text_light"])])
        
        # Treeview styles
        self.style.configure("Treeview", 
                             background=self.colors["teal_light"],
                             foreground=self.colors["text_dark"],
                             fieldbackground=self.colors["teal_light"],
                             font=("Arial", 10))
        
        self.style.map("Treeview",
                       background=[("selected", self.colors["teal_medium"])],
                       foreground=[("selected", self.colors["text_light"])])
        
    def create_header(self):
        """Create the header area with user info and app controls."""
        header_frame = ttk.Frame(self.main_frame, padding="10 5 10 5")
        header_frame.pack(fill=tk.X, side=tk.TOP)
        
        # User info
        user_frame = ttk.Frame(header_frame)
        user_frame.pack(side=tk.LEFT)
        
        self.username_var = tk.StringVar(value=self.peer.username)
        username_label = ttk.Label(user_frame, text="Username: ")
        username_label.pack(side=tk.LEFT)
        
        username_entry = ttk.Entry(user_frame, textvariable=self.username_var, width=15)
        username_entry.pack(side=tk.LEFT)
        
        username_btn = ttk.Button(user_frame, text="Set", command=self.set_username)
        username_btn.pack(side=tk.LEFT, padx=5)
        
        # Node info
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side=tk.RIGHT)
        
        node_id_label = ttk.Label(info_frame, text=f"Node ID: {self.peer.id}")
        node_id_label.pack(side=tk.RIGHT, padx=5)
        
        node_addr_label = ttk.Label(info_frame, text=f"Address: {self.peer.host}:{self.peer.port}")
        node_addr_label.pack(side=tk.RIGHT, padx=5)
    
    def create_sidebar(self):
        """Create the sidebar with peers, groups and connection controls."""
        # Create paned window for resizable sidebar
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar frame
        sidebar_frame = ttk.Frame(self.paned_window, padding="5")
        
        # Connection section
        connect_frame = ttk.LabelFrame(sidebar_frame, text="Connect to Peer", padding="5")
        connect_frame.pack(fill=tk.X, pady=5)
        
        host_frame = ttk.Frame(connect_frame)
        host_frame.pack(fill=tk.X, pady=2)
        ttk.Label(host_frame, text="Host:").pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="127.0.0.1")
        host_entry = ttk.Entry(host_frame, textvariable=self.host_var)
        host_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        port_frame = ttk.Frame(connect_frame)
        port_frame.pack(fill=tk.X, pady=2)
        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar()
        port_entry = ttk.Entry(port_frame, textvariable=self.port_var)
        port_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        connect_btn = ttk.Button(connect_frame, text="Connect", command=self.connect_to_peer)
        connect_btn.pack(fill=tk.X, pady=5)
        
        # Peers section with treeview
        peers_frame = ttk.LabelFrame(sidebar_frame, text="Peers", padding="5")
        peers_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.peers_tree = ttk.Treeview(peers_frame, show="tree", selectmode="browse")
        self.peers_tree.pack(fill=tk.BOTH, expand=True)
        self.peers_tree.heading("#0", text="Available Peers")
        self.peers_tree.bind("<Double-1>", self.on_peer_selected)
        
        # Groups section
        groups_frame = ttk.LabelFrame(sidebar_frame, text="Groups", padding="5")
        groups_frame.pack(fill=tk.X, pady=5)
        
        group_actions_frame = ttk.Frame(groups_frame)
        group_actions_frame.pack(fill=tk.X)
        
        create_group_btn = ttk.Button(group_actions_frame, text="Create Group", command=self.show_create_group_dialog)
        create_group_btn.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Groups treeview
        self.groups_tree = ttk.Treeview(groups_frame, show="tree", selectmode="browse", height=5)
        self.groups_tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.groups_tree.heading("#0", text="Your Groups")
        self.groups_tree.bind("<Double-1>", self.on_group_selected)
        
        # Add sidebar to paned window
        self.paned_window.add(sidebar_frame, weight=1)
    
    def create_chat_area(self):
        """Create the main chat area with message display and input box."""
        chat_frame = ttk.Frame(self.paned_window, padding="5")
        
        # Chat header showing current conversation
        self.chat_header_var = tk.StringVar(value="Broadcast Chat")
        chat_header = ttk.Label(chat_frame, textvariable=self.chat_header_var, font=("", 12, "bold"))
        chat_header.pack(fill=tk.X, pady=5)
        
        # Messages display area - now using Text widget instead of ScrolledText for more control
        self.messages_frame = ttk.Frame(chat_frame)
        self.messages_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create a canvas with scrollbar for custom chat bubbles
        self.chat_canvas = tk.Canvas(self.messages_frame, bg=self.colors["teal_light"])
        self.chat_scrollbar = ttk.Scrollbar(self.messages_frame, orient=tk.VERTICAL, command=self.chat_canvas.yview)
        self.chat_canvas.configure(yscrollcommand=self.chat_scrollbar.set)
        
        self.chat_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Create a frame inside canvas for message bubbles
        self.messages_container = ttk.Frame(self.chat_canvas, style="Content.TFrame")
        self.messages_container_id = self.chat_canvas.create_window((0, 0), window=self.messages_container, anchor='nw', width=self.chat_canvas.winfo_width())
        
        # Configure canvas scroll region when frame size changes
        self.messages_container.bind('<Configure>', lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox('all')))
        self.chat_canvas.bind('<Configure>', self.on_canvas_configure)
        
        # Bind mousewheel event for scrolling
        self.chat_canvas.bind_all("<MouseWheel>", lambda event: self.chat_canvas.yview_scroll(int(-1*(event.delta/120)), "units"))
        
        # Input area
        input_frame = ttk.Frame(chat_frame, padding="5")
        input_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(input_frame, textvariable=self.message_var)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        send_btn = ttk.Button(input_frame, text="Send", command=self.send_message)
        send_btn.pack(side=tk.RIGHT)
        
        # Add chat area to paned window with more weight
        self.paned_window.add(chat_frame, weight=3)
    
    def on_canvas_configure(self, event):
        """Update the width of the messages container when canvas is resized."""
        self.chat_canvas.itemconfig(self.messages_container_id, width=event.width)
    
    def create_status_bar(self):
        """Create the status bar at the bottom of the window."""
        status_frame = ttk.Frame(self.main_frame, relief=tk.SUNKEN, padding="2")
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_var = tk.StringVar(value=f"Connected: {len(self.peer.connections)} peers")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT)
        
        # Update status periodically
        self.update_status()
    
    def update_status(self):
        """Update the status bar with current connection information."""
        connected_peers = len(self.peer.connections)
        self.status_var.set(f"Connected: {connected_peers} peers")
        
        # Schedule next update
        self.root.after(5000, self.update_status)
    
    def refresh_sidebar(self):
        """Refresh the peers and groups lists in the sidebar."""
        # Clear existing items
        for item in self.peers_tree.get_children():
            self.peers_tree.delete(item)
        
        for item in self.groups_tree.get_children():
            self.groups_tree.delete(item)
        
        # Add broadcast chat
        self.peers_tree.insert("", "end", "broadcast", text="Broadcast", tags=("broadcast",))
        
        # Add direct peers
        for peer_id, (host, port) in self.peer.peers.items():
            username = f"user_{peer_id}"  # Default username format
            for msg_list in self.peer.message_history.values():
                for msg in msg_list:
                    if msg.get('from') == peer_id and 'from_username' in msg:
                        username = msg['from_username']
                        break
            
            peer_text = f"{username} ({host}:{port})"
            self.peers_tree.insert("", "end", peer_id, text=peer_text, tags=("peer",))
        
        # Add groups
        for group_name in self.peer.groups:
            self.groups_tree.insert("", "end", group_name, text=group_name, tags=("group",))
    
    def create_message_bubble(self, username, content, timestamp, is_sent=False, is_system=False):
        """Create a message bubble in the chat display."""
        # Create frame for this message
        msg_frame = ttk.Frame(self.messages_container, style="Content.TFrame")
        msg_frame.pack(fill=tk.X, padx=10, pady=5, anchor='e' if is_sent else 'w')
        
        # For system messages (connections, disconnections, etc.)
        if is_system:
            system_frame = ttk.Frame(msg_frame, style="Content.TFrame")
            system_frame.pack(fill=tk.X)
            
            # System message with light background
            system_label = tk.Label(
                system_frame, 
                text=content,
                bg=self.colors["system_msg"],
                fg=self.colors["text_dark"],
                padx=10,
                pady=5,
                wraplength=400,
                justify=tk.CENTER,
                relief=tk.GROOVE,
                font=("Arial", 9)
            )
            system_label.pack(fill=tk.X, padx=20)
            return
        
        # Message container aligns to right for sent messages, left for received
        bubble_frame = ttk.Frame(msg_frame, style="Content.TFrame")
        bubble_frame.pack(side=tk.RIGHT if is_sent else tk.LEFT)
        
        # Username label
        if not is_sent:  # Only show username for received messages
            name_label = tk.Label(
                bubble_frame,
                text=username,
                bg=self.colors["teal_light"],
                fg=self.colors["teal_dark"],
                anchor='w',
                font=("Arial", 9, "bold")
            )
            name_label.pack(anchor='w', padx=5)
        
        # Message bubble
        bubble_bg = self.colors["bubble_sent"] if is_sent else self.colors["bubble_received"]
        message_label = tk.Label(
            bubble_frame,
            text=content,
            bg=bubble_bg,
            fg=self.colors["text_dark"],
            padx=10,
            pady=8,
            wraplength=350,  # Limit width to create wrapping
            justify=tk.LEFT,
            anchor='w',
            relief=tk.GROOVE,
            borderwidth=1
        )
        message_label.pack(fill=tk.X, padx=5)
        
        # Timestamp label
        time_label = tk.Label(
            bubble_frame,
            text=timestamp,
            bg=bubble_bg,
            fg=self.colors["timestamp"],
            font=("Arial", 7),
            anchor='e' if is_sent else 'w'
        )
        time_label.pack(anchor='e' if is_sent else 'w', padx=5)
    
    def clear_chat_display(self):
        """Clear all messages from the chat display."""
        # Destroy all child widgets of the messages container
        for widget in self.messages_container.winfo_children():
            widget.destroy()
    
    def handle_message_received(self, chat_id, from_username, content, encrypted, is_group=False):
        """Handle received message and update UI accordingly."""
        # Format timestamp
        timestamp = time.strftime("%H:%M:%S")
        
        # If this is the current chat, append to display
        if chat_id == self.current_chat:
            # Add message bubble
            self.create_message_bubble(from_username, content, timestamp, is_sent=False)
            
            # Scroll to bottom
            self.chat_canvas.update_idletasks()
            self.chat_canvas.yview_moveto(1.0)
        
        # Update UI (bold unread messages)
        if chat_id != self.current_chat:
            if is_group:
                self.groups_tree.item(chat_id, tags=("unread",))
            else:
                if chat_id in self.peers_tree.get_children():
                    self.peers_tree.item(chat_id, tags=("unread",))
        
        # Make sure the treeview is updated
        self.refresh_sidebar()
    
    def handle_peer_connected(self, peer_id, username):
        """Handle new peer connection event."""
        # Update sidebar
        self.refresh_sidebar()
        
        # Notify in current chat
        system_message = f"--- {username} ({peer_id}) connected ---"
        self.create_message_bubble("", system_message, "", is_system=True)
        
        # Scroll to bottom
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)
        
        # Update status
        self.update_status()
    
    def handle_peer_disconnected(self, peer_id):
        """Handle peer disconnection event."""
        # Find username for the peer
        username = f"user_{peer_id}"
        for msg_list in self.peer.message_history.values():
            for msg in msg_list:
                if msg.get('from') == peer_id and 'from_username' in msg:
                    username = msg['from_username']
                    break
        
        # Update sidebar
        self.refresh_sidebar()
        
        # Notify in current chat
        system_message = f"--- {username} ({peer_id}) disconnected ---"
        self.create_message_bubble("", system_message, "", is_system=True)
        
        # Scroll to bottom
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)
        
        # Update status
        self.update_status()
    
    def handle_group_created(self, group_name, members):
        """Handle new group creation event."""
        # Update sidebar
        self.refresh_sidebar()
        
        # Notify in current chat
        member_count = len(members)
        system_message = f"--- Group '{group_name}' created with {member_count} members ---"
        self.create_message_bubble("", system_message, "", is_system=True)
        
        # Scroll to bottom
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)
    
    def on_peer_selected(self, event):
        """Handle peer selection in the sidebar."""
        selection = self.peers_tree.selection()
        if selection:
            selected_id = selection[0]
            
            # Switch to selected chat
            self.switch_chat(selected_id)
    
    def on_group_selected(self, event):
        """Handle group selection in the sidebar."""
        selection = self.groups_tree.selection()
        if selection:
            group_name = selection[0]
            
            # Switch to selected group chat
            self.switch_chat(group_name, is_group=True)
    
    def switch_chat(self, chat_id, is_group=False):
        """Switch to a different chat conversation."""
        self.current_chat = chat_id
        
        # Update header
        if chat_id == "broadcast":
            self.chat_header_var.set("Broadcast Chat")
        elif is_group:
            self.chat_header_var.set(f"Group: {chat_id}")
        else:
            # Find username for the peer
            username = f"user_{chat_id}"
            for msg_list in self.peer.message_history.values():
                for msg in msg_list:
                    if msg.get('from') == chat_id and 'from_username' in msg:
                        username = msg['from_username']
                        break
            self.chat_header_var.set(f"Chat with {username}")
        
        # Clear unread indicator
        if is_group:
            self.groups_tree.item(chat_id, tags=("group",))
        else:
            if chat_id in self.peers_tree.get_children():
                self.peers_tree.item(chat_id, tags=("peer",))
        
        # Clear existing messages
        self.clear_chat_display()
        
        # Load message history
        if chat_id in self.peer.message_history:
            for msg in self.peer.message_history[chat_id]:
                # Format timestamp
                timestamp = time.strftime("%H:%M:%S", time.localtime(msg['timestamp']))
                
                # Get username
                from_username = msg.get('from_username', msg['from'])
                
                # Determine if message was sent by us
                is_sent = msg['from'] == self.peer.id
                
                # Create bubble
                self.create_message_bubble(from_username, msg['content'], timestamp, is_sent=is_sent)
        
        # Scroll to bottom
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)
    
    def send_message(self, event=None):
        """Send a message in the current chat."""
        message = self.message_var.get().strip()
        if not message:
            return
        
        # Clear input field
        self.message_var.set("")
        
        # Get current timestamp
        timestamp = time.strftime("%H:%M:%S")
        
        # Update UI immediately with sent message
        self.create_message_bubble(self.peer.username, message, timestamp, is_sent=True)
        
        # Scroll to bottom
        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)
        
        # Send message based on current chat
        if self.current_chat == "broadcast":
            self.peer.send_message(message)
        elif self.current_chat in self.peer.groups:
            self.peer.send_message(message, group=self.current_chat)
        else:
            self.peer.send_message(message, to_peer=self.current_chat)
    
    def connect_to_peer(self):
        """Connect to a peer using the host/port from the UI."""
        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()
        
        if not host or not port_str:
            messagebox.showerror("Connection Error", "Host and port are required")
            return
        
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                raise ValueError("Invalid port range")
        except ValueError:
            messagebox.showerror("Connection Error", "Port must be a valid number between 1-65535")
            return
        
        # Try to connect
        success = self.peer.connect_to_peer(host, port)
        
        if success:
            messagebox.showinfo("Connection", f"Successfully connected to {host}:{port}")
            self.port_var.set("")  # Clear port field for next connection
        else:
            messagebox.showerror("Connection Error", f"Failed to connect to {host}:{port}")
    
    def set_username(self):
        """Set a new username for this peer."""
        username = self.username_var.get().strip()
        
        if not username:
            messagebox.showerror("Username Error", "Username cannot be empty")
            return
        
        self.peer.set_username(username)
        messagebox.showinfo("Username", f"Username changed to {username}")
    
    def show_create_group_dialog(self):
        """Show dialog to create a new group."""
        if not self.peer.peers:
            messagebox.showinfo("Create Group", "No peers connected. Connect to peers first.")
            return
        
        # Create dialog window
        dialog = tk.Toplevel(self.root)
        dialog.title("Create Group")
        dialog.geometry("300x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Group name field
        name_frame = ttk.Frame(dialog, padding="10")
        name_frame.pack(fill=tk.X)
        
        ttk.Label(name_frame, text="Group Name:").pack(anchor=tk.W)
        group_name_var = tk.StringVar()
        group_name_entry = ttk.Entry(name_frame, textvariable=group_name_var)
        group_name_entry.pack(fill=tk.X, pady=5)
        
        # Members selection
        members_frame = ttk.LabelFrame(dialog, text="Select Members", padding="10")
        members_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Checkboxes for each peer
        peer_vars = {}
        for peer_id, (host, port) in self.peer.peers.items():
            # Find username if available
            username = f"user_{peer_id}"
            for msg_list in self.peer.message_history.values():
                for msg in msg_list:
                    if msg.get('from') == peer_id and 'from_username' in msg:
                        username = msg['from_username']
                        break
            
            peer_vars[peer_id] = tk.BooleanVar(value=False)
            ttk.Checkbutton(
                members_frame,
                text=f"{username} ({peer_id})",
                variable=peer_vars[peer_id]
            ).pack(anchor=tk.W, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(dialog, padding="10")
        button_frame.pack(fill=tk.X)
        
        def on_create():
            group_name = group_name_var.get().strip()
            if not group_name:
                messagebox.showerror("Error", "Group name is required", parent=dialog)
                return
            
            # Get selected members
            selected_members = [peer_id for peer_id, var in peer_vars.items() if var.get()]
            
            if not selected_members:
                messagebox.showerror("Error", "Select at least one member", parent=dialog)
                return
            
            # Create the group
            success = self.peer.create_group(group_name, selected_members)
            
            if success:
                dialog.destroy()
                # Switch to the new group chat
                self.refresh_sidebar()
                self.switch_chat(group_name, is_group=True)
            else:
                messagebox.showerror("Error", "Failed to create group", parent=dialog)
        
        ttk.Button(button_frame, text="Create", command=on_create).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT, padx=5)
    
    def on_close(self):
        """Handle window close event."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.peer.shutdown()
            self.root.destroy()


# def main():
#     """Main function to start the P2P chat application."""
#     # Parse command line arguments
#     parser = argparse.ArgumentParser(description='P2P Chat Application')
#     parser.add_argument('--host', default='127.0.0.1', help='Host IP address')
#     parser.add_argument('--port', type=int,
                        
def main():
    """Main function to start the P2P chat application."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='P2P Chat Application')
    parser.add_argument('--host', default='127.0.0.1', help='Host IP address')
    parser.add_argument('--port', type=int, required=True, help='Port number')
    parser.add_argument('--bootstrap', help='Bootstrap node in format host:port')
    
    args = parser.parse_args()
    
    # Set up bootstrap nodes if provided
    bootstrap_nodes = []
    if args.bootstrap:
        try:
            bootstrap_host, bootstrap_port = args.bootstrap.split(':')
            bootstrap_port = int(bootstrap_port)
            bootstrap_nodes.append((bootstrap_host, bootstrap_port))
        except ValueError:
            print("Error: Bootstrap node must be in format host:port")
            sys.exit(1)
    
    # Initialize the peer
    peer = Peer(args.host, args.port, bootstrap_nodes)
    
    # Start the peer
    peer.start()
    
    # Create and start the UI
    root = tk.Tk()
    app = ChatUI(root, peer)
    root.mainloop()


if __name__ == "__main__":
    main()

