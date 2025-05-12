// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

//import "./RSALibrary.sol";
import "@openzeppelin/contracts/utils/cryptography/RSA.sol";

/**
@notice you can use RSAVerifier simple library instead of openzeppelin if you want
 */

contract RSAVerifier {

    function verifyRSA(
        bytes32 digest, //expectedHash
        bytes memory s, //signature
        bytes memory e, //exponent
        bytes memory n //modulus
         ) public view returns (bool valid) {
            
       return RSA.pkcs1Sha256(
         digest, //expectedHash
         s, //signature
         e, //exponent
         n //modulus 
    );
    }
     
}
