import os
import base64
import hashlib
import hmac
from typing import Tuple, Dict

class EnvelopeEncryptionEngine:
    """
    Implements NIST-compliant Envelope Encryption:
    Data is encrypted under a unique ephemeral Data Encryption Key (DEK).
    The DEK is encrypted under the Root Key Encryption Key (KEK).
    """

    def __init__(self, root_kek_passphrase: str):
        salt = b"NIST-Envelope-Root-Salt-AhmadMuntaser"
        self.kek = hashlib.pbkdf2_hmac("sha256", root_kek_passphrase.encode(), salt, iterations=150000)

    def _encrypt_dek(self, dek: bytes) -> bytes:
        nonce = os.urandom(16)
        stream_key = hmac.new(self.kek, nonce, hashlib.sha256).digest()
        cipher_dek = bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(dek)])
        auth_tag = hmac.new(self.kek, nonce + cipher_dek, hashlib.sha256).digest()
        return nonce + auth_tag + cipher_dek

    def _decrypt_dek(self, encrypted_dek: bytes) -> bytes:
        nonce = encrypted_dek[:16]
        auth_tag = encrypted_dek[16:48]
        cipher_dek = encrypted_dek[48:]
        expected_tag = hmac.new(self.kek, nonce + cipher_dek, hashlib.sha256).digest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("KEK integrity verification failure: Tampered encrypted DEK.")
        stream_key = hmac.new(self.kek, nonce, hashlib.sha256).digest()
        return bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(cipher_dek)])

    def encrypt_payload(self, plaintext: str) -> Dict[str, str]:
        # Generate fresh 256-bit DEK
        dek = os.urandom(32)

        # Encrypt plaintext with DEK
        nonce = os.urandom(16)
        stream_key = hmac.new(dek, nonce, hashlib.sha256).digest()
        plain_bytes = plaintext.encode("utf-8")
        cipher_data = bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(plain_bytes)])
        data_auth_tag = hmac.new(dek, nonce + cipher_data, hashlib.sha256).digest()
        encrypted_data = nonce + data_auth_tag + cipher_data

        # Encrypt DEK under KEK
        encrypted_dek = self._encrypt_dek(dek)

        return {
            "encrypted_dek": base64.b64encode(encrypted_dek).decode("utf-8"),
            "ciphertext": base64.b64encode(encrypted_data).decode("utf-8")
        }

    def decrypt_payload(self, envelope: Dict[str, str]) -> str:
        encrypted_dek = base64.b64decode(envelope["encrypted_dek"])
        encrypted_data = base64.b64decode(envelope["ciphertext"])

        # Recover DEK
        dek = self._decrypt_dek(encrypted_dek)

        # Decrypt payload using recovered DEK
        nonce = encrypted_data[:16]
        auth_tag = encrypted_data[16:48]
        cipher_data = encrypted_data[48:]
        expected_tag = hmac.new(dek, nonce + cipher_data, hashlib.sha256).digest()
        if not hmac.compare_digest(auth_tag, expected_tag):
            raise ValueError("DEK payload integrity failure: Tampered payload.")
        stream_key = hmac.new(dek, nonce, hashlib.sha256).digest()
        plain = bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(cipher_data)])
        return plain.decode("utf-8")
