#!/usr/bin/env python3
"""
Secure Cryptographic Message System - GUI Launcher

This script launches the professional GUI application for the cryptographic system.
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.gui.crypto_gui import CryptoGUI


def main():
    """
    Main entry point for GUI application.
    
    Launches the Secure Cryptographic Message System GUI.
    """
    try:
        app = CryptoGUI()
        print("="*60)
        print("Secure Cryptographic Message System")
        print("="*60)
        print("\n✓ GUI initialized successfully")
        print("✓ Ready to encrypt/decrypt messages")
        print("\nFeatures:")
        print("  • 256-bit SECP256K1 elliptic curve cryptography")
        print("  • Schnorr digital signatures for authentication")
        print("  • RC6-GCM authenticated encryption")
        print("  • Professional tabbed interface")
        print("  • Message history and export")
        print("\nClose this window to exit the application.\n")
        
        app.mainloop()
    except Exception as e:
        print(f"Error launching GUI: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
