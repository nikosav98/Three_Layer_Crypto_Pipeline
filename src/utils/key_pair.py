from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

class KeyPair:
    """
    Utility class for SECP256K1 elliptic curve key pair management.
    
    Provides methods for generating key pairs and extracting coordinates
    from public keys for cryptographic operations.
    """
    
    @staticmethod
    def generate():
        """
        Generate a new SECP256K1 key pair.
        
        Returns:
            tuple: (private_key, public_key) - EC key objects
        """
        # Generates a private key on the SECP256K1 curve
        private_key = ec.generate_private_key(ec.SECP256K1())
        # Extracts the public key from the private key
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def get_coordinates(public_key):
        """
        Extract (x, y) coordinates from an EC public key.
        
        Args:
            public_key: EC public key object (from cryptography library)
            
        Returns:
            tuple: (x, y) - 256-bit coordinates as integers
            
        Raises:
            ValueError: If key is not an EC public key or coordinates cannot be extracted
            
        Example:
            >>> private_key, public_key = KeyPair.generate()
            >>> x, y = KeyPair.get_coordinates(public_key)
            >>> print(f"Public key point: ({hex(x)}, {hex(y)})")
        """
        try:
            # Extract the public numbers from the key
            public_numbers = public_key.public_numbers()
            
            # Return x and y coordinates
            return (public_numbers.x, public_numbers.y)
        except AttributeError:
            raise ValueError(
                f"Invalid public key format. Expected EC public key, got {type(public_key)}"
            )
        except Exception as e:
            raise ValueError(f"Failed to extract coordinates from public key: {e}")
        
    @staticmethod
    def from_coordinates(coordinates : tuple):
        """
        Reconstruct an EC public key object from its x and y coordinates.
        
        Args:
            x (int): The x-coordinate of the public key point.
            y (int): The y-coordinate of the public key point.
            
        Returns:
            ec.EllipticCurvePublicKey: The reconstructed public key object.
        """
        try:
            # 1. Create PublicNumbers object using the specific curve (SECP256K1)
            public_numbers = ec.EllipticCurvePublicNumbers(
                x=coordinates[0],
                y=coordinates[1],
                curve=ec.SECP256K1()
            )
            # 2. Convert numbers back into a usable key object
            return public_numbers.public_key()
        except Exception as e:
            raise ValueError(f"Failed to reconstruct public key from coordinates: {e}")