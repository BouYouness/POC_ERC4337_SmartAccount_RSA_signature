// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./RSALibrary.sol";

contract RSAVerifier {

    function verifyRSA(
        bytes memory signature,
        bytes32 expectedHash,
        bytes memory modulus,
        bytes memory exponent
         ) public view returns (bool valid) {
            
       return RSALibrary.rsaVerify(
        signature,
        expectedHash,
        modulus,
        exponent
    );
    }

     
}
