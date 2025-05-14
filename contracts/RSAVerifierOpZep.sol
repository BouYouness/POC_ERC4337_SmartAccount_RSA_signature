// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/RSA.sol";

contract RSAVerifierOPZep {
    event GasUsed(uint256 gasUsed);

    function verifyRSA(
        bytes32 digest, //expectedHash
        bytes memory s, //signature
        bytes memory e, //exponent
        bytes memory n //modulus
    ) public view returns (bool valid) {
        return
            RSA.pkcs1Sha256(
                digest, //expectedHash
                s, //signature
                e, //exponent
                n //modulus
            );
    }

    function testGas(
        bytes32 digest,
        bytes memory s,
        bytes memory e,
        bytes memory n
    ) public returns (bool isValid, uint256 gasUsed) {
        uint256 startGas = gasleft();
        isValid = verifyRSA(digest, s, e, n);
        gasUsed = startGas - gasleft();
        emit GasUsed(gasUsed);
    }
}
