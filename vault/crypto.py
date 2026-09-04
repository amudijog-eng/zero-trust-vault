import os
import base64
import hashlib
import hmac

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

class VaultCrypto:
    """Provides authenticated cryptographic encryption for sensitive credentials."""

    def __init__(self, master_passphrase: str):
        # Derive a 256-bit key using PBKDF2 HMAC SHA-256
        salt = b"ZeroTrustSaltAhmadMuntaser2026"
        self.key = hashlib.pbkdf2_hmac("sha256", master_passphrase.encode(), salt, iterations=100000)

    def encrypt(self, plaintext: str) -> str:
        if HAS_CRYPTOGRAPHY:
            aesgcm = AESGCM(self.key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
            combined = nonce + ciphertext
            return base64.b64encode(combined).decode("utf-8")
        else:
            # High-security fallback: HMAC-SHA256 authenticated XOR stream cipher
            nonce = os.urandom(16)
            stream_key = hmac.new(self.key, nonce, hashlib.sha256).digest()
            plain_bytes = plaintext.encode("utf-8")
            cipher_bytes = bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(plain_bytes)])
            auth_tag = hmac.new(self.key, nonce + cipher_bytes, hashlib.sha256).digest()
            combined = nonce + auth_tag + cipher_bytes
            return base64.b64encode(combined).decode("utf-8")

    def decrypt(self, encrypted_payload: str) -> str:
        data = base64.b64decode(encrypted_payload)
        if HAS_CRYPTOGRAPHY:
            aesgcm = AESGCM(self.key)
            nonce = data[:12]
            ciphertext = data[12:]
            return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        else:
            nonce = data[:16]
            auth_tag = data[16:48]
            cipher_bytes = data[48:]
            expected_tag = hmac.new(self.key, nonce + cipher_bytes, hashlib.sha256).digest()
            if not hmac.compare_digest(auth_tag, expected_tag):
                raise ValueError("Cryptographic Integrity Verification Failed! Tampered payload.")
            stream_key = hmac.new(self.key, nonce, hashlib.sha256).digest()
            decrypted = bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(cipher_bytes)])
            return decrypted.decode("utf-8")
