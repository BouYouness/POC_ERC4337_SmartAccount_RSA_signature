# POC of RSA Signature Validation and ERC-4337 Smart Account

This project contains **two Proof of Concept** smart contract implementations:

## RSA Signature Validation Smart Contract

This POC demonstrates **how to validate an RSA signature** inside a smart contract using Solidity.

### Features:

- Accepts a signature, exponent, modulus, and expected hash.
- Performs **modular exponentiation**.
- Compares the decrypted signature result against the expected hash to validate.

### How to Do an End-to-End Test?
After deploying your RSA Verifier contract and generating the RSA values, you can run a full test that verifies the signature from start to finish.

**Steps :**
1. Compile the Contracts:
    
   ```
   npm run compile 
   ```

2. Deploy the Contract:

   ```
   npm run deploy
   ```

3. Prepare RSA Test Values:
  
   Ensure you’ve generated the RSA signature, modulus, and exponent using the Bash script in scripts file:

   ```
   chmod +x scripts/generate_rsa_values.sh
   ./scripts/generate_rsa_values.sh
   ```
4. Copy the outputs signature, modulus, and expected hash and past them in  test script.

5. Run the Test:
 
   ```
   npm run test
   ```
   The test will:
   
    - Deploy the verifier contract.
    - Use the generated RSA parameters.
    - Confirm whether the signature validation passes.





