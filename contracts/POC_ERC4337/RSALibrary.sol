// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library RSALibrary {
    
    /**
     * @notice Verifies RSA signature using modular exponentiation.
     * @param signature The RSA signature.
     * @param expectedHash The expected hash (message).
     * @param modulus RSA modulus.
     * @param exponent RSA exponent.
     * @return True if valid, false otherwise.
     */
     
    function rsaVerify(
        bytes memory signature,
        bytes32 expectedHash,
        bytes memory modulus,
        bytes memory exponent
    ) internal view returns (bool) {
        bytes memory result = modexp(signature, exponent, modulus);

        // Grab the last 32 bytes (SHA-256 outputs 32 bytes)
        bytes32 resultHash;
        assembly {
            resultHash := mload(add(result, mload(result)))
        }

        return resultHash == expectedHash;
    }

    
     //Perform modular exponentiation using Ethereum precompile.

    function modexp(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bytes memory output) {
        uint256 baseLen = base.length;
        uint256 expLen = exponent.length;
        uint256 modLen = modulus.length;

        bytes memory input = abi.encodePacked(
            uint256(baseLen),
            uint256(expLen),
            uint256(modLen),
            base,
            exponent,
            modulus
        );

        output = new bytes(modLen);

        assembly {
            if iszero(staticcall(not(0), 5, add(input, 32), mload(input), add(output, 32), modLen)) {
                revert(0, 0)
            }
        }
    }
}
