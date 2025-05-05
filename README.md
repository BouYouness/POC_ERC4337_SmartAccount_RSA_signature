# POC of RSA Signature Validation and ERC-4337 Smart Account

This project contains **two Proof of Concept (POC)** smart contract implementations:

## RSA Signature Validation Smart Contract

This POC demonstrates **how to validate an RSA signature** inside a smart contract using Solidity.

### Features:

- Accepts a signature, exponent, modulus, and expected hash.
- Performs **modular exponentiation**.
- Compares the decrypted signature result against the expected hash to validate.

### 🛠️ How to Use:

1. Run the Bash script to generate RSA values:

   ```bash
   chmod +x scripts/generate_rsa_values.sh
   ./scripts/generate_rsa_values.sh

