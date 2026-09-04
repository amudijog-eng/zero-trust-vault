# 🔐 Zero-Trust Vault
### **Enterprise Cryptographic Secret Enclave & Tamper-Proof Audit Ledger**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Security: Zero Trust](https://img.shields.io/badge/Architecture-Zero--Trust-purple.svg)]()
[![Cryptography: AES-256-GCM](https://img.shields.io/badge/Crypto-AES--256--GCM-green.svg)]()

Engineered by **Ahmad Muntaser Mohd Alamoudi** — Software Developer & Cybersecurity Specialist.

---

## 🏛️ Architecture & Principles

**Zero-Trust Vault** is a microservice designed following the core tenets of Zero-Trust Architecture:
1. **Never Trust, Always Verify**: Every principal, service, or process must authenticate and hold verified permissions.
2. **Authenticated Cryptography**: All stored secrets are encrypted at rest using AES-256-GCM with PBKDF2 HMAC-SHA256 key derivation.
3. **Immutable Audit Trail**: Employs a cryptographic hash chain (Merkle ledger) where any unauthorized tampering of historical access logs breaks the mathematical chain and flags an alert immediately.

---

## 🚀 Quickstart

### Python Usage

```python
from vault.engine import SecretVaultEngine

# Initialize Vault with Master Key
vault = SecretVaultEngine("ProductionMasterPassphrase2026!")

# Securely Store Secret
vault.set_secret("STRIPE_API_KEY", "sk_live_998234827419", principal="service-worker-1")

# Retrieve Secret
token = vault.get_secret("STRIPE_API_KEY", principal="service-worker-1")

# Verify Mathematical Integrity of Access Ledger
assert vault.ledger.verify_integrity() == True
```

---

## 🧪 Unit Tests

```bash
python -m unittest discover -s tests
```

---

## 🐳 Docker Deployment

```bash
docker build -t zero-trust-vault .
docker run -p 8000:8000 zero-trust-vault
```

---

## 📄 License

Licensed under the MIT License. See `LICENSE` for details.
