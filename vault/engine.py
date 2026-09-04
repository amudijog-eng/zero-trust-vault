from vault.crypto import VaultCrypto
from vault.audit_ledger import AuditLedger

class SecretVaultEngine:
    """Zero-Trust Engine controlling encrypted secret lifecycle."""

    def __init__(self, master_key: str):
        self.crypto = VaultCrypto(master_key)
        self.ledger = AuditLedger()
        self._store = {}

    def set_secret(self, key: str, value: str, principal: str = "admin") -> dict:
        encrypted = self.crypto.encrypt(value)
        self._store[key] = encrypted
        self.ledger.log("SECRET_STORE", principal, f"Secret '{key}' stored")
        return {"key": key, "status": "STORED"}

    def get_secret(self, key: str, principal: str = "admin") -> str:
        if key not in self._store:
            self.ledger.log("SECRET_NOT_FOUND", principal, f"Attempted read for '{key}'")
            raise KeyError(f"Secret '{key}' does not exist")

        self.ledger.log("SECRET_ACCESS", principal, f"Secret '{key}' retrieved")
        encrypted = self._store[key]
        return self.crypto.decrypt(encrypted)

    def delete_secret(self, key: str, principal: str = "admin") -> bool:
        if key in self._store:
            del self._store[key]
            self.ledger.log("SECRET_REVOKED", principal, f"Secret '{key}' deleted")
            return True
        return False
