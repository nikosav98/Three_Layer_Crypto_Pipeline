"""
Example: Running a secure server.

This example shows how to start the secure server that listens for
client connections and handles encrypted messages.

Usage:
    python examples/run_server.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.network.server import SecureServer
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def main():
    """Run the secure server."""
    print("=" * 60)
    print("Secure Server - Cryptography Course Project")
    print("=" * 60)
    
    # Create server
    server = SecureServer(host='0.0.0.0', port=5000, max_clients=10)
    
    print(f"\nStarting server on 0.0.0.0:5000...")
    print("Press Ctrl+C to stop\n")
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\nShutting down server...")
        server.stop()
        print("Server stopped.")

if __name__ == "__main__":
    main()
