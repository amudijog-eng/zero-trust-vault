import hashlib
import json
from datetime import datetime, timezone

class AuditLedger:
    """Cryptographically verifiable, immutable audit log using chained SHA-256 hashes."""

    def __init__(self):
        self.entries = []
        # Genesis block
        self._append_entry("GENESIS", "SYSTEM", "Audit ledger initialized")

    def log(self, action: str, principal: str, details: str) -> dict:
        return self._append_entry(action, principal, details)

    def _append_entry(self, action: str, principal: str, details: str) -> dict:
        prev_hash = self.entries[-1]["hash"] if self.entries else "0" * 64
        timestamp = datetime.now(timezone.utc).isoformat()

        payload = f"{prev_hash}:{timestamp}:{action}:{principal}:{details}"
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        entry = {
            "index": len(self.entries),
            "timestamp": timestamp,
            "action": action,
            "principal": principal,
            "details": details,
            "prev_hash": prev_hash,
            "hash": entry_hash
        }
        self.entries.append(entry)
        return entry

    def verify_integrity(self) -> bool:
        for i in range(1, len(self.entries)):
            curr = self.entries[i]
            prev = self.entries[i - 1]

            if curr["prev_hash"] != prev["hash"]:
                return False

            expected_payload = f"{curr['prev_hash']}:{curr['timestamp']}:{curr['action']}:{curr['principal']}:{curr['details']}"
            if hashlib.sha256(expected_payload.encode('utf-8')).hexdigest() != curr["hash"]:
                return False
        return True
