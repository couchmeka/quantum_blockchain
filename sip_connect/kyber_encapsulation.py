from typing import Dict, Tuple
import base64
from cryptography.fernet import Fernet
from crystals_kyber import kyber512


class KyberEncapsulation:
    def __init__(self):
        self.session_keys = {}

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber keypair"""
        return kyber512.keygen()

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Generate shared secret and ciphertext"""
        shared_secret, ciphertext = kyber512.encap(public_key)
        return shared_secret, ciphertext

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Recover shared secret from ciphertext"""
        return kyber512.decap(private_key, ciphertext)


def encrypt_with_kyber(message: bytes, public_key: bytes) -> Dict[str, bytes]:
    """Encrypt message using Kyber KEM"""
    kyber = KyberEncapsulation()

    shared_secret, ciphertext = kyber.encapsulate(public_key)
    fernet = Fernet(base64.urlsafe_b64encode(shared_secret))
    encrypted_data = fernet.encrypt(message)

    return {
        'ciphertext': ciphertext,
        'encrypted_data': encrypted_data
    }


def decrypt_with_kyber(encrypted_package: Dict[str, bytes], private_key: bytes) -> bytes:
    """Decrypt message using Kyber KEM"""
    kyber = KyberEncapsulation()

    shared_secret = kyber.decapsulate(private_key, encrypted_package['ciphertext'])
    fernet = Fernet(base64.urlsafe_b64encode(shared_secret))
    return fernet.decrypt(encrypted_package['encrypted_data'])