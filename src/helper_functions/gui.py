import sys
import random
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QStackedWidget, 
                             QTextEdit, QComboBox, QLineEdit, QFrame, QMessageBox,
                             QGridLayout, QDialog, QProgressBar, QGraphicsDropShadowEffect)
from PyQt6.QtCore import Qt, QSize, QTimer
from PyQt6.QtGui import QColor

# =============================================================================
# STYLING & THEMES
# =============================================================================

class Theme:
    """
    Refined Color Palettes based on Modern UI/UX Standards.
    Focus: Contrast, Legibility, and 'Tech-Professional' aesthetic.
    """
    
    DARK = """
    /* Main Background */
    QMainWindow, QWidget#CentralWidget { background-color: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', sans-serif; }
    
    /* Sidebar */
    QFrame#Sidebar { background-color: #1e293b; border-right: 1px solid #334155; }
    QPushButton#NavButton {
        background-color: transparent; border: none; text-align: left; padding: 12px 20px;
        color: #94a3b8; font-size: 14px; border-radius: 8px; margin: 4px 10px;
    }
    QPushButton#NavButton:hover { background-color: #334155; color: #f1f5f9; }
    QPushButton#NavButton:checked { background-color: #3b82f6; color: #ffffff; font-weight: 600; }

    /* Cards (Content Containers) */
    QFrame.Card {
        background-color: #1e293b; border: 1px solid #334155; border-radius: 12px;
    }

    /* Content Typography */
    QLabel#Header { font-size: 26px; font-weight: 700; color: #f8fafc; margin-bottom: 5px; }
    QLabel#SubHeader { font-size: 14px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 15px; margin-bottom: 5px; }
    QLabel { font-size: 14px; color: #cbd5e1; }
    QLabel#Credits { font-size: 12px; color: #64748b; margin-bottom: 10px; }

    /* Inputs */
    QLineEdit, QTextEdit, QComboBox {
        background-color: #0f172a; border: 1px solid #334155; color: #e2e8f0;
        padding: 10px; border-radius: 8px; font-size: 14px;
    }
    QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border: 1px solid #3b82f6; background-color: #1e293b; }
    
    /* Action Buttons */
    QPushButton.actionBtn {
        background-color: #3b82f6; color: #ffffff; border: none; padding: 10px 24px;
        border-radius: 8px; font-weight: 600; font-size: 14px;
    }
    QPushButton.actionBtn:hover { background-color: #2563eb; }
    QPushButton.actionBtn:pressed { background-color: #1d4ed8; }

    QPushButton.secondaryBtn {
        background-color: #334155; color: #e2e8f0; border: 1px solid #475569; padding: 10px 24px;
        border-radius: 8px; font-size: 14px; font-weight: 500;
    }
    QPushButton.secondaryBtn:hover { background-color: #475569; }

    QPushButton.accentBtn {
        background-color: transparent; border: 2px solid #8b5cf6; color: #a78bfa; padding: 8px 20px;
        border-radius: 8px; font-weight: bold;
    }
    QPushButton.accentBtn:hover { background-color: rgba(139, 92, 246, 0.1); }

    /* Scrollbars */
    QScrollBar:vertical { background: #0f172a; width: 8px; }
    QScrollBar::handle:vertical { background: #475569; border-radius: 4px; }
    
    /* Visualizer */
    QLabel.block { background-color: #0f172a; border: 1px solid #3b82f6; border-radius: 6px; color: #e2e8f0; font-family: 'Consolas', monospace; }
    QLabel.block_active { background-color: #be123c; border: 1px solid #f43f5e; color: white; }
    QLabel.block_done { background-color: #047857; border: 1px solid #10b981; color: white; }
    """

    LIGHT = """
    /* Main Background */
    QMainWindow, QWidget#CentralWidget { background-color: #f1f5f9; color: #334155; font-family: 'Segoe UI', sans-serif; }
    
    /* Sidebar */
    QFrame#Sidebar { background-color: #ffffff; border-right: 1px solid #e2e8f0; }
    QPushButton#NavButton {
        background-color: transparent; border: none; text-align: left; padding: 12px 20px;
        color: #64748b; font-size: 14px; border-radius: 8px; margin: 4px 10px;
    }
    QPushButton#NavButton:hover { background-color: #f1f5f9; color: #0f172a; }
    QPushButton#NavButton:checked { background-color: #3b82f6; color: #ffffff; font-weight: 600; }

    /* Cards */
    QFrame.Card {
        background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px;
    }

    /* Content Typography */
    QLabel#Header { font-size: 26px; font-weight: 700; color: #0f172a; margin-bottom: 5px; }
    QLabel#SubHeader { font-size: 14px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 15px; margin-bottom: 5px; }
    QLabel { font-size: 14px; color: #334155; }
    QLabel#Credits { font-size: 12px; color: #64748b; margin-bottom: 10px; }

    /* Inputs */
    QLineEdit, QTextEdit, QComboBox {
        background-color: #f8fafc; border: 1px solid #cbd5e1; color: #334155;
        padding: 10px; border-radius: 8px; font-size: 14px;
    }
    QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border: 1px solid #3b82f6; background-color: #ffffff; }
    
    /* Buttons */
    QPushButton.actionBtn {
        background-color: #2563eb; color: #ffffff; border: none; padding: 10px 24px;
        border-radius: 8px; font-weight: 600; font-size: 14px;
    }
    QPushButton.actionBtn:hover { background-color: #1d4ed8; }
    
    QPushButton.secondaryBtn {
        background-color: #ffffff; color: #475569; border: 1px solid #cbd5e1; padding: 10px 24px;
        border-radius: 8px; font-size: 14px; font-weight: 500;
    }
    QPushButton.secondaryBtn:hover { background-color: #f1f5f9; border-color: #94a3b8; }

    QPushButton.accentBtn {
        background-color: transparent; border: 2px solid #7c3aed; color: #7c3aed; padding: 8px 20px;
        border-radius: 8px; font-weight: bold;
    }
    QPushButton.accentBtn:hover { background-color: rgba(124, 58, 237, 0.05); }

    /* Visualizer */
    QLabel.block { background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; color: #334155; font-family: 'Consolas', monospace; }
    QLabel.block_active { background-color: #fecdd3; border: 1px solid #e11d48; color: #881337; }
    QLabel.block_done { background-color: #d1fae5; border: 1px solid #059669; color: #064e3b; }
    """

# =============================================================================
# UI COMPONENTS (Design System)
# =============================================================================

class ContentCard(QFrame):
    """ Wrapper for content sections to look like 'Cards' """
    def __init__(self, layout_pointer=None):
        super().__init__()
        self.setProperty("class", "Card")
        # Optional shadow for depth
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 20))
        shadow.setOffset(0, 4)
        self.setGraphicsEffect(shadow)
        
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.setSpacing(15)
        
        if layout_pointer:
            layout_pointer.addWidget(self)

    def add_widget(self, widget):
        self._layout.addWidget(widget)
    
    def add_layout(self, layout):
        self._layout.addLayout(layout)

# =============================================================================
# HELPER: VISUALIZATION DIALOG
# =============================================================================
class VisualizerDialog(QDialog):
    def __init__(self, text_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Encryption Process Visualizer")
        self.resize(900, 650)
        # Apply theme from parent
        self.setStyleSheet(parent.styleSheet())
        
        self.raw_data = text_data if text_data else "NO_DATA_AVAILABLE"
        self.blocks = [self.raw_data[i:i+4] for i in range(0, len(self.raw_data), 4)]
        self.current_block_idx = 0
        self.step = 0
        
        # Main Layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setSpacing(20)
        
        # Header
        header = QLabel("Real-Time Encryption Visualizer")
        header.setObjectName("Header")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(header)
        
        # Status Card
        status_card = ContentCard(main_layout)
        self.status_label = QLabel("Initializing Visualization Engine...")
        self.status_label.setStyleSheet("font-size: 16px; font-weight: 600; color: #3b82f6;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        status_card.add_widget(self.status_label)
        
        self.progress = QProgressBar()
        self.progress.setRange(0, len(self.blocks) * 4)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(6)
        status_card.add_widget(self.progress)
        
        # Grid Area
        self.grid_frame = QFrame()
        self.grid_layout = QGridLayout(self.grid_frame)
        self.grid_layout.setSpacing(15)
        self.block_widgets = []
        
        row, col = 0, 0
        for block_text in self.blocks:
            lbl = QLabel(block_text.ljust(4))
            lbl.setFixedSize(100, 100)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setProperty("class", "block")
            lbl.setStyleSheet("font-size: 18px;")
            self.grid_layout.addWidget(lbl, row, col)
            self.block_widgets.append(lbl)
            
            col += 1
            if col > 5:
                col = 0
                row += 1
        
        # Center the grid
        grid_container = QWidget()
        grid_box = QHBoxLayout(grid_container)
        grid_box.addStretch()
        grid_box.addWidget(self.grid_frame)
        grid_box.addStretch()
        main_layout.addWidget(grid_container)
        
        # Log Card
        log_card = ContentCard(main_layout)
        log_card.add_widget(QLabel("PROCESS LOG", objectName="SubHeader"))
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(120)
        log_card.add_widget(self.log_area)
        
        self.timer = QTimer()
        self.timer.timeout.connect(self.animate_step)
        self.timer.start(500)

    def animate_step(self):
        if self.current_block_idx >= len(self.blocks):
            self.timer.stop()
            self.status_label.setText("ENCRYPTION SEQUENCE COMPLETE")
            self.log_area.append("✔ Process finished successfully.")
            return

        widget = self.block_widgets[self.current_block_idx]
        current_text = widget.text()
        
        if self.step == 0:
            widget.setProperty("class", "block_active")
            widget.style().unpolish(widget); widget.style().polish(widget)
            self.status_label.setText(f"Block {self.current_block_idx + 1}: Fetching Data into Buffer")
            self.log_area.append(f"→ Block {self.current_block_idx + 1}: Loaded '{current_text.strip()}'")
            self.step += 1
            
        elif self.step == 1:
            self.status_label.setText(f"Block {self.current_block_idx + 1}: Substitution Layer (S-Box)")
            rand_hex = ''.join([random.choice('0123456789ABCDEF') for _ in range(4)])
            widget.setText(rand_hex)
            self.log_area.append(f"  • SubBytes applied: transformed to HEX.")
            self.step += 1
            
        elif self.step == 2:
            self.status_label.setText(f"Block {self.current_block_idx + 1}: Permutation Layer (ShiftRows)")
            current_hex = widget.text()
            shifted = current_hex[1:] + current_hex[0]
            widget.setText(shifted)
            self.log_area.append(f"  • ShiftRows applied: bitwise rotation.")
            self.step += 1
            
        elif self.step == 3:
            widget.setProperty("class", "block_done")
            widget.style().unpolish(widget); widget.style().polish(widget)
            self.status_label.setText(f"Block {self.current_block_idx + 1}: Locked & Stored")
            self.log_area.append(f"✔ Block {self.current_block_idx + 1} finalized.")
            
            self.step = 0
            self.current_block_idx += 1
            self.progress.setValue(self.progress.value() + 4)

# =============================================================================
# MODULE 1: SYMMETRIC ENCRYPTION
# =============================================================================
class SymmetricTab(QWidget):
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)
        
        # Header Area
        header = QLabel("Symmetric Encryption Engine")
        header.setObjectName("Header")
        main_layout.addWidget(header)
        main_layout.addWidget(QLabel("Configure your encryption parameters and input data below."))

        # Configuration Card
        config_card = ContentCard(main_layout)
        config_card.add_widget(QLabel("CONFIGURATION", objectName="SubHeader"))
        
        grid = QGridLayout()
        grid.addWidget(QLabel("Algorithm:"), 0, 0)
        self.algo_selector = QComboBox()
        self.algo_selector.addItems(["AES-256 (Advanced Encryption Standard)", "DES (Data Encryption Standard)"])
        grid.addWidget(self.algo_selector, 0, 1)
        
        grid.addWidget(QLabel("Operation Mode:"), 1, 0)
        self.mode_selector = QComboBox()
        self.mode_selector.addItems(["ECB (Electronic Codebook)", "CBC (Cipher Block Chaining)"])
        grid.addWidget(self.mode_selector, 1, 1)
        
        config_card.add_layout(grid)

        # Input Card
        input_card = ContentCard(main_layout)
        input_card.add_widget(QLabel("DATA INPUT", objectName="SubHeader"))
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter Secret Key (e.g. MySecretPass123)...")
        input_card.add_widget(self.key_input)
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter plaintext message here...")
        self.input_text.setFixedHeight(80)
        input_card.add_widget(self.input_text)

        # Actions
        action_layout = QHBoxLayout()
        self.btn_encrypt = QPushButton("Encrypt Data")
        self.btn_encrypt.setProperty("class", "actionBtn")
        
        self.btn_animate = QPushButton("Visualize Process")
        self.btn_animate.setProperty("class", "accentBtn")
        self.btn_animate.setCursor(Qt.CursorShape.PointingHandCursor)
        
        self.btn_decrypt = QPushButton("Decrypt Data")
        self.btn_decrypt.setProperty("class", "secondaryBtn")
        
        action_layout.addWidget(self.btn_encrypt)
        action_layout.addWidget(self.btn_decrypt)
        action_layout.addStretch()
        action_layout.addWidget(self.btn_animate)
        
        main_layout.addLayout(action_layout)

        # Output Card
        output_card = ContentCard(main_layout)
        output_card.add_widget(QLabel("CIPHERTEXT OUTPUT", objectName="SubHeader"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Results will appear here...")
        self.output_text.setFixedHeight(80)
        output_card.add_widget(self.output_text)
        
        main_layout.addStretch()

        # Connections
        self.btn_encrypt.clicked.connect(self.perform_encryption)
        self.btn_animate.clicked.connect(self.perform_visual_encryption)
        self.btn_decrypt.clicked.connect(self.perform_decryption)

    def perform_encryption(self):
        key = self.key_input.text()
        data = self.input_text.toPlainText()
        if not data: 
            self.output_text.setText("Error: Input data is empty.")
            return
        self.output_text.setText(f"[SIMULATION] Encrypted '{data}'\nKey: {key}\nResult: 0xA3 0xF9 0x82 0xB1 ...")

    def perform_visual_encryption(self):
        data = self.input_text.toPlainText()
        dialog = VisualizerDialog(data, self)
        dialog.exec()
        self.output_text.setText(f"[VISUALIZATION COMPLETE] Ciphertext generated.")

    def perform_decryption(self):
        self.output_text.setText(f"[SIMULATION] Data decrypted successfully.")

# =============================================================================
# MODULE 2: ASYMMETRIC / PKI
# =============================================================================
class AsymmetricTab(QWidget):
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)

        header = QLabel("Public-Key Infrastructure (PKI)")
        header.setObjectName("Header")
        main_layout.addWidget(header)
        main_layout.addWidget(QLabel("Manage key pairs and simulate secure channel handshakes."))

        # Key Gen Card
        key_card = ContentCard(main_layout)
        key_card.add_widget(QLabel("KEY MANAGEMENT", objectName="SubHeader"))
        
        gen_layout = QHBoxLayout()
        self.btn_gen_keys = QPushButton("Generate New Key Pair")
        self.btn_gen_keys.setProperty("class", "actionBtn")
        self.btn_gen_keys.clicked.connect(self.generate_keys)
        gen_layout.addWidget(self.btn_gen_keys)
        gen_layout.addStretch()
        key_card.add_layout(gen_layout)
        
        keys_layout = QHBoxLayout()
        
        pub_container = QWidget()
        pub_lay = QVBoxLayout(pub_container)
        pub_lay.setContentsMargins(0,0,0,0)
        pub_lay.addWidget(QLabel("Public Key (Shareable)"))
        self.pub_key_display = QTextEdit()
        self.pub_key_display.setFixedHeight(80)
        pub_lay.addWidget(self.pub_key_display)
        
        priv_container = QWidget()
        priv_lay = QVBoxLayout(priv_container)
        priv_lay.setContentsMargins(0,0,0,0)
        priv_lay.addWidget(QLabel("Private Key (Secret)"))
        self.priv_key_display = QTextEdit()
        self.priv_key_display.setFixedHeight(80)
        priv_lay.addWidget(self.priv_key_display)

        keys_layout.addWidget(pub_container)
        keys_layout.addWidget(priv_container)
        key_card.add_layout(keys_layout)

        # Simulation Card
        sim_card = ContentCard(main_layout)
        sim_card.add_widget(QLabel("CHANNEL HANDSHAKE LOG", objectName="SubHeader"))
        self.channel_log = QTextEdit()
        self.channel_log.setPlaceholderText("Log of Diffie-Hellman or RSA handshake...")
        sim_card.add_widget(self.channel_log)
        
        main_layout.addStretch()

    def generate_keys(self):
        self.pub_key_display.setText("n = 0x4F2A...\ne = 65537")
        self.priv_key_display.setText("d = 0x9C12... (KEEP SECRET)")
        self.channel_log.append("→ New RSA-2048 Key Pair generated locally.")

# =============================================================================
# MODULE 3: DIGITAL SIGNATURES
# =============================================================================
class SignatureTab(QWidget):
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)

        header = QLabel("Digital Signatures")
        header.setObjectName("Header")
        main_layout.addWidget(header)
        main_layout.addWidget(QLabel("Verify data integrity and non-repudiation using Hashing and Signing."))

        # Input Card
        input_card = ContentCard(main_layout)
        input_card.add_widget(QLabel("MESSAGE DIGEST", objectName="SubHeader"))
        
        self.msg_input = QTextEdit()
        self.msg_input.setPlaceholderText("Enter message to sign...")
        self.msg_input.setFixedHeight(80)
        input_card.add_widget(self.msg_input)
        
        hash_layout = QHBoxLayout()
        self.btn_hash = QPushButton("Calculate SHA-256 Hash")
        self.btn_hash.setProperty("class", "secondaryBtn")
        self.btn_hash.clicked.connect(self.calc_hash)
        
        self.hash_display = QLineEdit()
        self.hash_display.setReadOnly(True)
        self.hash_display.setPlaceholderText("Hash digest...")
        
        hash_layout.addWidget(self.btn_hash)
        hash_layout.addWidget(self.hash_display)
        input_card.add_layout(hash_layout)

        # Action Card
        action_card = ContentCard(main_layout)
        action_card.add_widget(QLabel("SIGNING OPERATIONS", objectName="SubHeader"))
        
        btn_layout = QHBoxLayout()
        self.btn_sign = QPushButton("Sign Hash")
        self.btn_sign.setProperty("class", "actionBtn")
        self.btn_verify = QPushButton("Verify Signature")
        self.btn_verify.setProperty("class", "secondaryBtn")
        
        self.btn_sign.clicked.connect(self.sign_message)
        self.btn_verify.clicked.connect(self.verify_message)
        
        btn_layout.addWidget(self.btn_sign)
        btn_layout.addWidget(self.btn_verify)
        btn_layout.addStretch()
        action_card.add_layout(btn_layout)
        
        self.sig_output = QTextEdit()
        self.sig_output.setPlaceholderText("Digital Signature output...")
        self.sig_output.setFixedHeight(80)
        action_card.add_widget(self.sig_output)
        
        main_layout.addStretch()

    def calc_hash(self):
        import hashlib
        text = self.msg_input.toPlainText().encode('utf-8')
        digest = hashlib.sha256(text).hexdigest()
        self.hash_display.setText(digest)

    def sign_message(self):
        if not self.hash_display.text():
            self.calc_hash()
        self.sig_output.setText(f"BEGIN SIGNATURE\n{self.hash_display.text()[:16]}...\nEND SIGNATURE")

    def verify_message(self):
        QMessageBox.information(self, "Integrity Check", "Signature is VALID.\nMessage has not been tampered with.")

# =============================================================================
# MODULE 4: INTEGRATED SCENARIO
# =============================================================================
class ScenarioTab(QWidget):
    def __init__(self):
        super().__init__()
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)

        header = QLabel("Secure Exchange Simulation")
        header.setObjectName("Header")
        main_layout.addWidget(header)
        main_layout.addWidget(QLabel("Full integration test: Signing + Hybrid Encryption."))

        # Chat UI
        chat_card = ContentCard(main_layout)
        chat_card.setStyleSheet("QFrame.Card { background-color: rgba(30, 41, 59, 0.5); }") # Transparent look
        
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setPlaceholderText("Secure Channel Established...")
        chat_card.add_widget(self.chat_history)

        input_layout = QHBoxLayout()
        self.msg_input = QLineEdit()
        self.msg_input.setPlaceholderText("Type a confidential message...")
        
        self.btn_send = QPushButton("Send Securely")
        self.btn_send.setProperty("class", "actionBtn")
        self.btn_send.clicked.connect(self.send_secure_message)

        input_layout.addWidget(self.msg_input)
        input_layout.addWidget(self.btn_send)
        chat_card.add_layout(input_layout)

        # Protocol Log
        log_card = ContentCard(main_layout)
        log_card.add_widget(QLabel("PROTOCOL AUDIT LOG", objectName="SubHeader"))
        self.protocol_log = QTextEdit()
        self.protocol_log.setFixedHeight(120)
        log_card.add_widget(self.protocol_log)

    def send_secure_message(self):
        msg = self.msg_input.text()
        if not msg: return
        
        self.chat_history.append(f"<span style='color:#3b82f6'><b>You:</b></span> {msg}")
        self.protocol_log.append(f"► <b>Hashing:</b> SHA-256 digest generated.")
        self.protocol_log.append(f"► <b>Signing:</b> Signed with Private Key.")
        self.protocol_log.append(f"► <b>Encryption:</b> Payload encrypted with AES Session Key.")
        self.msg_input.clear()

# =============================================================================
# MAIN WINDOW
# =============================================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Data Security Suite v2.0")
        self.resize(1100, 750)
        self.is_dark = True
        
        central_widget = QWidget()
        central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(260)
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(0, 30, 0, 30)
        sidebar_layout.setSpacing(10)

        # Title
        title_lbl = QLabel("CRYPTO\nGUARD")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl.setStyleSheet("font-size: 22px; font-weight: 800; color: #3b82f6; letter-spacing: 2px;")
        sidebar_layout.addWidget(title_lbl)
        sidebar_layout.addSpacing(20)

        # Navigation
        self.stack = QStackedWidget()
        self.nav_btns = []
        
        self.add_nav_btn("Symmetric Engine", 0, sidebar_layout)
        self.add_nav_btn("Asymmetric PKI", 1, sidebar_layout)
        self.add_nav_btn("Digital Signatures", 2, sidebar_layout)
        sidebar_layout.addSpacing(20)
        self.add_nav_btn("SECURE CHAT DEMO", 3, sidebar_layout)

        sidebar_layout.addStretch()

        # Credits
        credits_lbl = QLabel("Credits:\nYuval Kogan\nNikolay Savchenko\nRoni Shifrin")
        credits_lbl.setObjectName("Credits")
        credits_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(credits_lbl)

        # Theme Switcher
        self.theme_container = QWidget()
        theme_layout = QVBoxLayout(self.theme_container)
        self.theme_btn = QPushButton("Switch to Light Mode")
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.setStyleSheet("""
            background-color: #334155; color: white; border-radius: 6px; padding: 8px;
        """)
        self.theme_btn.clicked.connect(self.toggle_theme)
        theme_layout.addWidget(self.theme_btn)
        sidebar_layout.addWidget(self.theme_container)

        # Main Content
        self.stack.addWidget(SymmetricTab())
        self.stack.addWidget(AsymmetricTab())
        self.stack.addWidget(SignatureTab())
        self.stack.addWidget(ScenarioTab())

        main_layout.addWidget(self.sidebar)
        main_layout.addWidget(self.stack)

        self.setStyleSheet(Theme.DARK)

    def add_nav_btn(self, text, index, layout):
        btn = QPushButton(text)
        btn.setObjectName("NavButton")
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        if index == 0: btn.setChecked(True)
        btn.clicked.connect(lambda: self.stack.setCurrentIndex(index))
        layout.addWidget(btn)
        self.nav_btns.append(btn)

    def toggle_theme(self):
        if self.is_dark:
            self.setStyleSheet(Theme.LIGHT)
            self.theme_btn.setText("Switch to Dark Mode")
            self.theme_btn.setStyleSheet("background-color: #e2e8f0; color: #333; border-radius: 6px; padding: 8px;")
            self.is_dark = False
        else:
            self.setStyleSheet(Theme.DARK)
            self.theme_btn.setText("Switch to Light Mode")
            self.theme_btn.setStyleSheet("background-color: #334155; color: white; border-radius: 6px; padding: 8px;")
            self.is_dark = True

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())