"""
Professional GUI for Secure Cryptographic Message Exchange.

Features:
- Secure client interface with encryption/decryption
- Real-time message history
- Key management
- Status monitoring
- Multi-threaded network operations
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import sys
import os
from datetime import datetime
from typing import Optional, Callable

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.utils.key_pair import KeyPair
from src.utils.email_message import EmailMessage
from src.algorithms.key_exchange.exchange_manager import ExchangeManager
from src.core.crypto_utils import OperationStatus, format_bytes_hex, format_size


class EncryptionWorker(threading.Thread):
    """Worker thread for encryption operations."""
    
    def __init__(self, callback: Callable, operation: str, *args, **kwargs):
        """
        Initialize encryption worker.
        
        Args:
            callback: Function to call with results
            operation: Operation name ('encrypt' or 'decrypt')
            *args: Operation arguments
            **kwargs: Operation keyword arguments
        """
        super().__init__(daemon=True)
        self.callback = callback
        self.operation = operation
        self.args = args
        self.kwargs = kwargs
        self.result = None
        self.error = None
    
    def run(self):
        """Execute the operation."""
        try:
            if self.operation == 'encrypt':
                self.result = self._encrypt()
            elif self.operation == 'decrypt':
                self.result = self._decrypt()
            else:
                self.error = f"Unknown operation: {self.operation}"
        except Exception as e:
            self.error = str(e)
        finally:
            self.callback(self.result, self.error)
    
    def _encrypt(self):
        """Perform encryption."""
        manager, message = self.args[:2]
        return manager.secure_send(EmailMessage(message))
    
    def _decrypt(self):
        """Perform decryption."""
        manager, bundle, priv_key = self.args[:3]
        return manager.secure_receive(bundle, priv_key)


class StatusBar(ttk.Frame):
    """Professional status bar widget for displaying operation status."""
    
    def __init__(self, parent, **kwargs):
        """
        Initialize status bar.
        
        Args:
            parent: Parent widget
            **kwargs: Frame options
        """
        super().__init__(parent, **kwargs)
        self.configure(height=40)
        
        # Status label with icon
        self.status_label = ttk.Label(
            self,
            text="✓ Ready",
            relief=tk.SUNKEN,
            anchor=tk.W,
            font=('Segoe UI', 10)
        )
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=8)
        
        # Progress indicator
        self.progress = ttk.Progressbar(
            self,
            mode='indeterminate',
            length=150
        )
        self.progress.pack(side=tk.RIGHT, padx=10, pady=8)
    
    def set_status(self, message: str, status: OperationStatus = None):
        """
        Set status message with color coding.
        
        Args:
            message: Status message
            status: Operation status
        """
        # Add icon based on status
        if status == OperationStatus.SUCCESS:
            icon = "✓"
            self.status_label.config(foreground="#27ae60", text=f"{icon} {message}")
            self.progress.stop()
        elif status == OperationStatus.ERROR:
            icon = "✗"
            self.status_label.config(foreground="#e74c3c", text=f"{icon} {message}")
            self.progress.stop()
        elif status == OperationStatus.PENDING:
            icon = "⟳"
            self.status_label.config(foreground="#3498db", text=f"{icon} {message}")
            self.progress.start()
        else:
            self.status_label.config(foreground="#2c3e50", text=f"• {message}")
    
    def start_operation(self, message: str):
        """Start operation with pending status."""
        self.set_status(message, OperationStatus.PENDING)
    
    def operation_complete(self, success: bool, message: str):
        """Mark operation complete with success/error status."""
        status = OperationStatus.SUCCESS if success else OperationStatus.ERROR
        self.set_status(message, status)


class CryptoGUI(tk.Tk):
    """Main GUI application for cryptographic system."""
    
    def __init__(self):
        """Initialize the application."""
        super().__init__()
        
        # Configuration
        self.title("🔐 Secure Cryptographic Message System")
        self.geometry("1200x800")
        self.resizable(True, True)
        
        # Set window icon color theme
        self.configure(bg='#f5f7fa')
        
        # Initialize data
        self.sender_private_key = None
        self.sender_public_key = None
        self.recipient_public_key = None
        self.recipient_private_key = None
        self.manager = None
        
        # Message history
        self.message_history = []
        
        # Create GUI
        self._create_styles()
        self._create_widgets()
        
        # Center window
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"+{x}+{y}")
    
    def _create_styles(self):
        """Create custom styles with modern appearance."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Color scheme - Modern dark blue and accent colors
        bg_color = '#f5f7fa'
        fg_color = '#2c3e50'
        accent_color = '#3498db'
        success_color = '#27ae60'
        error_color = '#e74c3c'
        border_color = '#bdc3c7'
        
        # Configure main background
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color, font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('TNotebook', background=bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', padding=[20, 10], font=('Segoe UI', 10, 'bold'))
        
        # Header styles
        style.configure('Header.TLabel', 
                       font=('Segoe UI', 18, 'bold'), 
                       foreground=accent_color,
                       background=bg_color)
        style.configure('SubHeader.TLabel', 
                       font=('Segoe UI', 12, 'bold'),
                       foreground=fg_color,
                       background=bg_color)
        
        # Status styles
        style.configure('Success.TLabel', 
                       foreground=success_color, 
                       font=('Segoe UI', 10),
                       background=bg_color)
        style.configure('Error.TLabel', 
                       foreground=error_color, 
                       font=('Segoe UI', 10),
                       background=bg_color)
        
        # Button styles
        style.configure('Accent.TButton',
                       font=('Segoe UI', 10, 'bold'))
        
        # LabelFrame styles
        style.configure('TLabelframe', 
                       background=bg_color,
                       foreground=fg_color,
                       borderwidth=2)
        style.configure('TLabelframe.Label',
                       font=('Segoe UI', 11, 'bold'),
                       background=bg_color,
                       foreground=accent_color)
    
    def _create_widgets(self):
        """Create GUI widgets with professional layout."""
        # Header frame with title
        header_frame = ttk.Frame(self)
        header_frame.pack(fill=tk.X, padx=15, pady=15)
        
        title_label = ttk.Label(
            header_frame,
            text="🔐 Secure Cryptographic Message System",
            style='Header.TLabel'
        )
        title_label.pack(anchor=tk.W)
        
        subtitle_label = ttk.Label(
            header_frame,
            text="256-bit SECP256K1 Elliptic Curve • Schnorr Signatures • RC6-GCM Encryption",
            style='SubHeader.TLabel',
            foreground='#7f8c8d'
        )
        subtitle_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Separator
        separator = ttk.Separator(self, orient=tk.HORIZONTAL)
        separator.pack(fill=tk.X, padx=15)
        
        # Main container with padding
        main_container = ttk.Frame(self)
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self._create_key_tab()
        self._create_message_tab()
        self._create_history_tab()
        self._create_settings_tab()
        
        # Status bar
        self.status_bar = StatusBar(self)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _create_key_tab(self):
        """Create professional key management tab."""
        frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(frame, text="🔑 Keys & Setup")
        
        # Title
        title = ttk.Label(frame, text="Key Pair Management", style='Header.TLabel')
        title.pack(anchor=tk.W, pady=(0, 15))
        
        subtitle = ttk.Label(
            frame,
            text="Generate and manage cryptographic key pairs for secure communication",
            foreground='#7f8c8d'
        )
        subtitle.pack(anchor=tk.W, pady=(0, 20))
        
        # Sender keys section
        sender_frame = self._create_key_section(frame, "👤 Sender Keys (Your Keys)")
        sender_frame.pack(fill=tk.X, pady=10)
        
        # Generate sender keys button with better styling
        sender_btn_frame = ttk.Frame(sender_frame)
        sender_btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        btn_gen_sender = ttk.Button(
            sender_btn_frame,
            text="Generate Sender Keys",
            command=self._generate_sender_keys,
            width=20
        )
        btn_gen_sender.pack(side=tk.LEFT, padx=0)
        
        # Sender keys info
        self.sender_keys_info = ttk.Label(
            sender_btn_frame,
            text="Not generated yet",
            foreground="#e74c3c",
            font=('Segoe UI', 10, 'bold')
        )
        self.sender_keys_info.pack(side=tk.LEFT, padx=20)
        
        # Recipient keys section
        recipient_frame = self._create_key_section(frame, "👥 Recipient Keys (Their Keys)")
        recipient_frame.pack(fill=tk.X, pady=10)
        
        # Generate recipient keys button
        recipient_btn_frame = ttk.Frame(recipient_frame)
        recipient_btn_frame.pack(fill=tk.X, pady=(0, 10))
        
        btn_gen_recipient = ttk.Button(
            recipient_btn_frame,
            text="Generate Recipient Keys",
            command=self._generate_recipient_keys,
            width=20
        )
        btn_gen_recipient.pack(side=tk.LEFT, padx=0)
        
        # Recipient keys info
        self.recipient_keys_info = ttk.Label(
            recipient_btn_frame,
            text="Not generated yet",
            foreground="#e74c3c",
            font=('Segoe UI', 10, 'bold')
        )
        self.recipient_keys_info.pack(side=tk.LEFT, padx=20)
        
        # Public key display section
        display_frame = ttk.LabelFrame(frame, text="📋 Public Key Coordinates", padding="15")
        display_frame.pack(fill=tk.BOTH, expand=True, pady=15)
        
        # Sender public key
        ttk.Label(display_frame, text="Sender Public Key (X, Y):", style='SubHeader.TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.sender_pubkey_text = scrolledtext.ScrolledText(
            display_frame,
            height=4,
            width=70,
            state=tk.DISABLED,
            font=('Consolas', 9),
            bg='#ecf0f1',
            relief=tk.FLAT
        )
        self.sender_pubkey_text.pack(fill=tk.X, pady=(0, 15))
        
        # Recipient public key
        ttk.Label(display_frame, text="Recipient Public Key (X, Y):", style='SubHeader.TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.recipient_pubkey_text = scrolledtext.ScrolledText(
            display_frame,
            height=4,
            width=70,
            state=tk.DISABLED,
            font=('Consolas', 9),
            bg='#ecf0f1',
            relief=tk.FLAT
        )
        self.recipient_pubkey_text.pack(fill=tk.X)
        
        # Instructions frame
        instructions_frame = ttk.LabelFrame(frame, text="📝 Instructions", padding="15")
        instructions_frame.pack(fill=tk.X, pady=(15, 0))
        
        info_text = (
            "To enable secure message encryption, follow these steps:\n\n"
            "1️⃣  Generate Sender Keys  →  Creates your cryptographic key pair\n"
            "2️⃣  Generate Recipient Keys  →  Creates recipient's key pair\n"
            "3️⃣  Go to Messages Tab  →  Ready to encrypt/decrypt messages\n\n"
            "Both key pairs are required for secure communication to work properly."
        )
        info_label = ttk.Label(
            instructions_frame,
            text=info_text,
            justify=tk.LEFT,
            foreground="#3498db",
            font=('Segoe UI', 10)
        )
        info_label.pack(anchor=tk.W)
    
    def _create_key_section(self, parent, title) -> ttk.Frame:
        """Create a key section frame."""
        frame = ttk.LabelFrame(parent, text=title, padding="10")
        return frame
    
    def _create_message_tab(self):
        """Create professional message encryption/decryption tab."""
        frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(frame, text="💬 Messages")
        
        # Title
        title = ttk.Label(frame, text="Encrypt & Decrypt Messages", style='Header.TLabel')
        title.pack(anchor=tk.W, pady=(0, 10))
        
        subtitle = ttk.Label(
            frame,
            text="Securely encrypt messages with RC6-GCM and authenticate with Schnorr signatures",
            foreground='#7f8c8d'
        )
        subtitle.pack(anchor=tk.W, pady=(0, 20))
        
        # Encryption section
        encrypt_frame = ttk.LabelFrame(frame, text="🔒 Encrypt Message", padding="15")
        encrypt_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(encrypt_frame, text="Message to Encrypt:", style='SubHeader.TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.encrypt_input = scrolledtext.ScrolledText(
            encrypt_frame,
            height=5,
            width=70,
            font=('Segoe UI', 10),
            bg='white',
            relief=tk.FLAT,
            borderwidth=1
        )
        self.encrypt_input.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        btn_encrypt = ttk.Button(
            encrypt_frame,
            text="🔐 Encrypt Message",
            command=self._encrypt_message
        )
        btn_encrypt.pack(side=tk.LEFT, padx=0, pady=(0, 10))
        
        ttk.Label(encrypt_frame, text="Encrypted Output:", style='SubHeader.TLabel').pack(anchor=tk.W, pady=(10, 5))
        self.encrypt_output = scrolledtext.ScrolledText(
            encrypt_frame,
            height=4,
            width=70,
            state=tk.DISABLED,
            font=('Consolas', 9),
            bg='#ecf0f1',
            relief=tk.FLAT
        )
        self.encrypt_output.pack(fill=tk.BOTH, expand=True)
        
        # Decryption section
        decrypt_frame = ttk.LabelFrame(frame, text="🔓 Decrypt Message", padding="15")
        decrypt_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        ttk.Label(decrypt_frame, text="Encrypted Message:", style='SubHeader.TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.decrypt_input = scrolledtext.ScrolledText(
            decrypt_frame,
            height=4,
            width=70,
            font=('Consolas', 9),
            bg='white',
            relief=tk.FLAT,
            borderwidth=1
        )
        self.decrypt_input.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        btn_decrypt = ttk.Button(
            decrypt_frame,
            text="🔑 Decrypt Message",
            command=self._decrypt_message
        )
        btn_decrypt.pack(side=tk.LEFT, padx=0, pady=(0, 10))
        
        ttk.Label(decrypt_frame, text="Decrypted Output:", style='SubHeader.TLabel').pack(anchor=tk.W, pady=(10, 5))
        self.decrypt_output = scrolledtext.ScrolledText(
            decrypt_frame,
            height=4,
            width=70,
            state=tk.DISABLED,
            font=('Segoe UI', 10),
            bg='#ecf0f1',
            relief=tk.FLAT
        )
        self.decrypt_output.pack(fill=tk.BOTH, expand=True)
    
    def _create_history_tab(self):
        """Create professional message history tab."""
        frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(frame, text="📜 History")
        
        # Title
        title = ttk.Label(frame, text="Message History", style='Header.TLabel')
        title.pack(anchor=tk.W, pady=(0, 10))
        
        subtitle = ttk.Label(
            frame,
            text="View and export all encrypted/decrypted messages",
            foreground='#7f8c8d'
        )
        subtitle.pack(anchor=tk.W, pady=(0, 20))
        
        # History display
        self.history_text = scrolledtext.ScrolledText(
            frame,
            height=25,
            width=80,
            state=tk.DISABLED,
            font=('Consolas', 9),
            bg='#ecf0f1',
            relief=tk.FLAT
        )
        self.history_text.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)
        
        btn_clear = ttk.Button(
            btn_frame,
            text="🗑️  Clear History",
            command=self._clear_history,
            width=20
        )
        btn_clear.pack(side=tk.LEFT, padx=5)
        
        btn_export = ttk.Button(
            btn_frame,
            text="💾 Export History",
            command=self._export_history,
            width=20
        )
        btn_export.pack(side=tk.LEFT, padx=5)
    
    def _create_settings_tab(self):
        """Create professional settings and info tab."""
        frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(frame, text="⚙️ Info & Settings")
        
        # Title
        title = ttk.Label(frame, text="System Information", style='Header.TLabel')
        title.pack(anchor=tk.W, pady=(0, 10))
        
        subtitle = ttk.Label(
            frame,
            text="Complete cryptographic system configuration and features",
            foreground='#7f8c8d'
        )
        subtitle.pack(anchor=tk.W, pady=(0, 20))
        
        # Create scrolled frame for content
        canvas = tk.Canvas(frame, highlightthickness=0, bg='#f5f7fa')
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # System Configuration Section
        config_frame = ttk.LabelFrame(scrollable_frame, text="🔐 Cryptographic Configuration", padding="15")
        config_frame.pack(fill=tk.X, pady=10, padx=5)
        
        config_text = (
            "Elliptic Curve:  SECP256K1 (256-bit)\n"
            "Symmetric Cipher:  RC6-GCM (128-bit blocks, 32 rounds)\n"
            "Authentication:  GHASH (Galois Counter Mode)\n"
            "Signature Scheme:  Schnorr (with SHA-256)\n"
            "Hash Function:  SHA-256\n"
            "Key Derivation:  SHA-256 based KDF"
        )
        config_label = ttk.Label(config_frame, text=config_text, justify=tk.LEFT, font=('Segoe UI', 10))
        config_label.pack(anchor=tk.W)
        
        # Session Parameters Section
        session_frame = ttk.LabelFrame(scrollable_frame, text="📊 Session Parameters", padding="15")
        session_frame.pack(fill=tk.X, pady=10, padx=5)
        
        session_text = (
            "Session Key Length:  256-bit (32 bytes)\n"
            "Initialization Vector:  96-bit (12 bytes)\n"
            "Authentication Tag:  128-bit (16 bytes)\n"
            "Block Size:  128-bit (16 bytes)"
        )
        session_label = ttk.Label(session_frame, text=session_text, justify=tk.LEFT, font=('Segoe UI', 10))
        session_label.pack(anchor=tk.W)
        
        # Security Features Section
        security_frame = ttk.LabelFrame(scrollable_frame, text="🛡️ Security Features", padding="15")
        security_frame.pack(fill=tk.X, pady=10, padx=5)
        
        features = [
            "✓ End-to-End Encryption (E2E)",
            "✓ Digital Signatures & Authentication",
            "✓ Message Integrity Verification",
            "✓ Tamper Detection & Prevention",
            "✓ Semantic Security (Probabilistic)",
            "✓ Forward Secrecy Support",
            "✓ Authenticated Encryption (AEAD)",
            "✓ Resistance to Timing Attacks"
        ]
        
        for feature in features:
            feature_label = ttk.Label(
                security_frame,
                text=feature,
                justify=tk.LEFT,
                font=('Segoe UI', 10),
                foreground='#27ae60'
            )
            feature_label.pack(anchor=tk.W, pady=2)
        
        # About Section
        about_frame = ttk.LabelFrame(scrollable_frame, text="ℹ️ About", padding="15")
        about_frame.pack(fill=tk.X, pady=10, padx=5)
        
        about_text = (
            "Secure Cryptographic Message System v1.0\n\n"
            "A professional-grade implementation of modern cryptographic\n"
            "algorithms for secure communication and message authentication.\n\n"
            "Features a complete 3-layer encryption pipeline combining\n"
            "elliptic curve cryptography, digital signatures, and\n"
            "authenticated encryption.\n\n"
            "© 2024 Cryptography Course"
        )
        about_label = ttk.Label(
            about_frame,
            text=about_text,
            justify=tk.LEFT,
            font=('Segoe UI', 10),
            foreground='#2c3e50'
        )
        about_label.pack(anchor=tk.W)
    
    # Key Management Methods
    
    def _generate_sender_keys(self):
        """Generate sender keys."""
        try:
            self.status_bar.start_operation("Generating sender keys...")
            self.sender_private_key, self.sender_public_key = KeyPair.generate()
            
            # Update UI
            self.sender_keys_info.config(
                text="✓ Generated",
                foreground="green"
            )
            
            # Display public key
            pub_x, pub_y = KeyPair.get_coordinates(self.sender_public_key)
            pubkey_display = f"X: {format_bytes_hex(pub_x.to_bytes(32, 'big'))}\nY: {format_bytes_hex(pub_y.to_bytes(32, 'big'))}"
            
            self.sender_pubkey_text.config(state=tk.NORMAL)
            self.sender_pubkey_text.delete(1.0, tk.END)
            self.sender_pubkey_text.insert(1.0, pubkey_display)
            self.sender_pubkey_text.config(state=tk.DISABLED)
            
            self.status_bar.operation_complete(True, "Sender keys generated successfully")
            messagebox.showinfo("Success", "Sender keys generated successfully!")
        except Exception as e:
            self.status_bar.operation_complete(False, f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate sender keys:\n{str(e)}")
    
    def _generate_recipient_keys(self):
        """Generate recipient keys."""
        try:
            self.status_bar.start_operation("Generating recipient keys...")
            self.recipient_private_key, self.recipient_public_key = KeyPair.generate()
            
            # Update UI
            self.recipient_keys_info.config(
                text="✓ Generated",
                foreground="green"
            )
            
            # Display public key
            pub_x, pub_y = KeyPair.get_coordinates(self.recipient_public_key)
            pubkey_display = f"X: {format_bytes_hex(pub_x.to_bytes(32, 'big'))}\nY: {format_bytes_hex(pub_y.to_bytes(32, 'big'))}"
            
            self.recipient_pubkey_text.config(state=tk.NORMAL)
            self.recipient_pubkey_text.delete(1.0, tk.END)
            self.recipient_pubkey_text.insert(1.0, pubkey_display)
            self.recipient_pubkey_text.config(state=tk.DISABLED)
            
            # Initialize manager
            if self.sender_private_key and self.recipient_public_key:
                self.manager = ExchangeManager(
                    self.sender_private_key,
                    self.recipient_public_key
                )
            
            self.status_bar.operation_complete(True, "Recipient keys generated successfully")
            messagebox.showinfo("Success", "Recipient keys generated successfully!")
        except Exception as e:
            self.status_bar.operation_complete(False, f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate recipient keys:\n{str(e)}")
    
    # Message Methods
    
    def _encrypt_message(self):
        """Encrypt a message."""
        if not self.manager:
            messagebox.showerror("Error", "Please generate keys first!")
            return
        
        message = self.encrypt_input.get(1.0, tk.END).strip()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to encrypt!")
            return
        
        try:
            self.status_bar.start_operation("Encrypting message...")
            
            # Encrypt in background thread
            def on_encrypt_complete(result, error):
                if error:
                    self.status_bar.operation_complete(False, f"Encryption failed")
                    self.after(0, lambda: messagebox.showerror("Error", f"Encryption failed:\n{error}"))
                else:
                    self.status_bar.operation_complete(True, "Message encrypted successfully")
                    
                    # Display result
                    import json
                    import base64
                    
                    bundle_json = {
                        'encrypted_key': result.encrypted_key.hex(),
                        'iv': base64.b64encode(result.iv).decode(),
                        'ciphertext': base64.b64encode(result.ciphertext).decode(),
                        'auth_tag': base64.b64encode(result.auth_tag).decode()
                    }
                    
                    output = json.dumps(bundle_json, indent=2)
                    self.after(0, lambda: self._update_encrypt_output(output, message))
                    
                    # Add to history
                    self.after(0, lambda: self._add_history_entry(
                        "ENCRYPT",
                        message,
                        format_size(len(output))
                    ))
            
            worker = EncryptionWorker(on_encrypt_complete, 'encrypt', self.manager, message)
            worker.start()
        
        except Exception as e:
            self.status_bar.operation_complete(False, f"Error: {str(e)}")
            messagebox.showerror("Error", f"Encryption error:\n{str(e)}")
    
    def _decrypt_message(self):
        """Decrypt a message."""
        messagebox.showinfo("Info", "Decrypt functionality requires deserialization of the encrypted bundle.\nThis would be implemented with full bundle parsing.")
    
    def _update_encrypt_output(self, output: str, original_message: str):
        """Update encryption output display."""
        self.encrypt_output.config(state=tk.NORMAL)
        self.encrypt_output.delete(1.0, tk.END)
        self.encrypt_output.insert(1.0, output)
        self.encrypt_output.config(state=tk.DISABLED)
    
    # History Methods
    
    def _add_history_entry(self, operation: str, message: str, size: str):
        """Add entry to history."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {operation}: {message[:50]}... ({size})\n"
        
        self.message_history.append(entry)
        
        self.history_text.config(state=tk.NORMAL)
        self.history_text.insert(tk.END, entry)
        self.history_text.see(tk.END)
        self.history_text.config(state=tk.DISABLED)
    
    def _clear_history(self):
        """Clear message history."""
        if messagebox.askyesno("Confirm", "Clear all history?"):
            self.message_history.clear()
            self.history_text.config(state=tk.NORMAL)
            self.history_text.delete(1.0, tk.END)
            self.history_text.config(state=tk.DISABLED)
            self.status_bar.set_status("History cleared")
    
    def _export_history(self):
        """Export history to file."""
        if not self.message_history:
            messagebox.showwarning("Warning", "No history to export!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.writelines(self.message_history)
                messagebox.showinfo("Success", f"History exported to:\n{file_path}")
                self.status_bar.set_status(f"History exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export history:\n{str(e)}")


def main():
    """Launch the GUI application."""
    app = CryptoGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
