import unittest
from vault.crypto import VaultCrypto
from vault.audit_ledger import AuditLedger
from vault.engine import SecretVaultEngine
from vault.envelope import EnvelopeEncryptionEngine

class TestZeroTrustVault(unittest.TestCase):
    def test_crypto_roundtrip(self):
        crypto = VaultCrypto("StrongMasterPassphrase2026!")
        secret = "SuperSecretAPIToken_998877"
        encrypted = crypto.encrypt(secret)
        self.assertNotEqual(secret, encrypted)
        decrypted = crypto.decrypt(encrypted)
        self.assertEqual(secret, decrypted)

    def test_envelope_encryption(self):
        env = EnvelopeEncryptionEngine("EnterpriseRootKEK_Key99!")
        envelope = env.encrypt_payload("ProductionDatabasePassword_DB445")
        self.assertIn("encrypted_dek", envelope)
        self.assertIn("ciphertext", envelope)
        recovered = env.decrypt_payload(envelope)
        self.assertEqual(recovered, "ProductionDatabasePassword_DB445")

    def test_audit_ledger_integrity(self):
        ledger = AuditLedger()
        ledger.log("LOGIN", "user1", "Successful MFA login")
        ledger.log("READ_SECRET", "user1", "Read API_KEY")
        self.assertTrue(ledger.verify_integrity())

        # Simulate tampering
        ledger.entries[1]["details"] = "Tampered unauthorized access"
        self.assertFalse(ledger.verify_integrity())

    def test_engine_secret_lifecycle(self):
        engine = SecretVaultEngine("MasterKey99")
        engine.set_secret("DB_PASSWORD", "db_pass_12345")
        self.assertEqual(engine.get_secret("DB_PASSWORD"), "db_pass_12345")
        self.assertTrue(engine.delete_secret("DB_PASSWORD"))
        with self.assertRaises(KeyError):
            engine.get_secret("DB_PASSWORD")

if __name__ == "__main__":
    unittest.main()
