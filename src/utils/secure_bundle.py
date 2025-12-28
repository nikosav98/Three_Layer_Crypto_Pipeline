import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

class SecureBundle:
    def __init__(self, ek: bytes, iv: bytes, c: bytes, t: bytes, sender_pub_key: ec.EllipticCurvePublicKey, sender_id: str):
        # Initializing private fields as per the diagram
        self.__ek = ek                 # Encrypted Key (byte[])
        self.__iv = iv                 # Nonce (byte[12])
        self.__c = c                   # Ciphertext (byte[])
        self.__t = t                   # Auth Tag (byte[16])
        self.__sender_pub_key = sender_pub_key # ECPublicKey object
        self.__sender_id = sender_id   # Sender ID (String)

    # Getters to allow controlled access to private fields
    def get_ek(self): return self.__ek
    def get_iv(self): return self.__iv
    def get_c(self): return self.__c
    def get_t(self): return self.__t
    def get_sender_pub_key(self): return self.__sender_pub_key
    def get_sender_id(self): return self.__sender_id
    
    # Property shortcuts for easier access
    @property
    def encrypted_key(self): return self.__ek
    
    @property
    def iv(self): return self.__iv
    
    @property
    def ciphertext(self): return self.__c
    
    @property
    def auth_tag(self): return self.__t
    
    @property
    def sender_public_key(self): return self.__sender_pub_key
    
    @property
    def sender_id(self): return self.__sender_id

    def serialize(self) -> str:
        """
        Converts the SecureBundle object into a JSON string for transmission.
        """
        # Convert the Public Key object into bytes so it can be stored in JSON
        pub_key_bytes = self.__sender_pub_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        # Map fields to a dictionary and Base64 encode all byte[] data
        bundle_dict = {
            "ek": base64.b64encode(self.__ek).decode('utf-8'),
            "iv": base64.b64encode(self.__iv).decode('utf-8'),
            "c": base64.b64encode(self.__c).decode('utf-8'),
            "t": base64.b64encode(self.__t).decode('utf-8'),
            "sender_pub_key": base64.b64encode(pub_key_bytes).decode('utf-8'),
            "sender_id": self.__sender_id
        }
        return json.dumps(bundle_dict)

    @classmethod
    def deserialize(cls, json_str: str):
        """
        Reconstructs the SecureBundle object from a JSON string.
        """
        data = json.loads(json_str)

        # Decode Base64 strings back into raw bytes
        ek = base64.b64decode(data['ek'])
        iv = base64.b64decode(data['iv'])
        c = base64.b64decode(data['c'])
        t = base64.b64decode(data['t'])
        pub_key_bytes = base64.b64decode(data['sender_pub_key'])

        # Reconstruct the ECPublicKey object from the raw X962 bytes
        sender_pub_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pub_key_bytes
        )

        return cls(ek, iv, c, t, sender_pub_key, data['sender_id'])