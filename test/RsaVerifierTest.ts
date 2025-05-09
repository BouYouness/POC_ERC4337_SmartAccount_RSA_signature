import { expect } from "chai";
import { ethers } from "hardhat";
import { createSign, generateKeyPairSync } from "crypto";
import { sha256 } from "@ethersproject/sha2";
import { toUtf8Bytes } from "@ethersproject/strings";
import { getBytes, hexlify } from "ethers";
import forge from "node-forge";

describe("RSAVerifier", function () {
  let verifier: any;

  let rsaValues: {
    signature: string;
    modulus: string;
    exponent: string;
    expectedHash: string;
  };

  // Helper function to extract modulus and exponent
  function extractModulus_Exponent(pemPublicKey: string): {
    modulus: Buffer;
    exponent: Buffer;
  } {
    const forgePublicKey = forge.pki.publicKeyFromPem(pemPublicKey);
    const nBytes = forge.util.hexToBytes(forgePublicKey.n.toString(16));
    const eBytes = forge.util.hexToBytes(forgePublicKey.e.toString(16));

    const modulus = Buffer.from(nBytes, "binary");
    const exponent = Buffer.from(eBytes, "binary");

    return { modulus, exponent };
  }

  before(async () => {
    const RSAVerifierFactory = await ethers.getContractFactory("RSAVerifier");
    verifier = await RSAVerifierFactory.deploy();
    await verifier.waitForDeployment();

    // Generate RSA key pair
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 0x10001, // 65537
      publicKeyEncoding: {
        type: "pkcs1",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs1",
        format: "pem",
      },
    });

    // Message for signing
    const message = "hi man";
    const expectedHash = sha256(toUtf8Bytes(message));

    // Create our signature
    const signer = createSign("RSA-SHA256");
    signer.update(message);
    signer.end();
    const signatureBuffer = signer.sign(privateKey);

    // Extract modulus and exponent using the helper function 
    const { modulus, exponent } = extractModulus_Exponent(publicKey);

    rsaValues = {
      signature: hexlify(signatureBuffer),
      modulus: hexlify(modulus),
      exponent: hexlify(exponent),
      expectedHash,
    };

    if (
      !rsaValues.signature ||
      !rsaValues.modulus ||
      !rsaValues.exponent ||
      !rsaValues.expectedHash
    ) {
      throw new Error("Missing RSA values from crypto module");
    }
  });

  it("should verify a valid RSA signature", async () => {
    const { signature, exponent, modulus, expectedHash } = rsaValues;

    const result = await verifier.verifyRSA(
      getBytes(signature),
      expectedHash,
      getBytes(modulus),
      getBytes(exponent)
    );

    expect(result).to.equal(true);
  });
   

  // testing with wrong hash message
  it("should fail when passing the wrong expectedHash", async () => {
    const { signature, exponent, modulus } = rsaValues;

    const wrongExpectedHash = sha256(toUtf8Bytes("hello"));
    const result = await verifier.verifyRSA(
      getBytes(signature),
      wrongExpectedHash,
      getBytes(modulus),
      getBytes(exponent)
    );

    expect(result).to.equal(false);
  });
});




