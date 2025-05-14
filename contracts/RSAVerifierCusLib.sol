// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./RSALibrary.sol";

contract RSAVerifierCusLib {
    event GasUsed(uint256 gasUsed);

    function verifyRSA1(
        bytes memory signature,
        bytes32 expectedHash,
        bytes memory modulus,
        bytes memory exponent
    ) public view returns (bool valid) {
        return RSALibrary.rsaVerify(signature, expectedHash, modulus, exponent);
    }

    function testGas(
        bytes memory signature,
        bytes32 expectedHash,
        bytes memory modulus,
        bytes memory exponent
    ) public returns (bool isValid, uint256 gasUsed) {
        uint256 startGas = gasleft();
        isValid = verifyRSA1(signature, expectedHash, modulus, exponent);
        gasUsed = startGas - gasleft();
        emit GasUsed(gasUsed);
    }
}
