// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@account-abstraction/contracts/core/BaseAccount.sol";
import "@account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "./RSALibrary.sol";

abstract contract RSAAccount is BaseAccount {
    bytes public modulus;
    bytes public exponent;

    /**
     * @notice Constructor initializes the RSA public key.
     * @param _modulus The RSA modulus part of the public key.
     * @param _exponent The RSA exponent part of the public key.
     */
    constructor(bytes memory _modulus, bytes memory _exponent) {
        modulus = _modulus;
        exponent = _exponent;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* ETH gas EntryPoint expects you to pay */
    ) external view override returns (uint256 validationData) {
        // SECURITY: Verify only EntryPoint can call this
        _requireFromEntryPoint();

        // Extract the signature from the user operation
        bytes memory signature = userOp.signature;

        // Verify the RSA signature (the message is the userOpHash)
        bool valid = RSALibrary.rsaVerify(
            signature,
            userOpHash,
            modulus,
            exponent
        );

        if (!valid) {
            return 1; // Signature invalid 🚫
        }
        return 0; // Signature valid
    }
}
