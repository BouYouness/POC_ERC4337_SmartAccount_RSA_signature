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
      expectedHash,
      getBytes(signature),
      getBytes(exponent),
      getBytes(modulus)
    );

    expect(result).to.equal(true);
  });
   

  // testing with wrong hash message
  it("should fail when passing the wrong expectedHash", async () => {
    const { signature, exponent, modulus } = rsaValues;

    const wrongExpectedHash = sha256(toUtf8Bytes("hello"));
    const result = await verifier.verifyRSA(
      wrongExpectedHash,
      getBytes(signature),
      getBytes(exponent),
      getBytes(modulus)
    );

    expect(result).to.equal(false);
  });
});


describe("RsaTwoMessagesVerifier", function () {
  let verifier: any;

  let signature1: string;
  let signature2: string;
  let expectedHash1: string;
  let expectedHash2: string;
  let modulusHex: string;
  let exponentHex: string;

  // Helper to extract modulus and exponent
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

    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicExponent: 0x10001,
      publicKeyEncoding: { type: "pkcs1", format: "pem" },
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
    });

    // Message 1 and Signature
    const message1 = "hey hello";
    expectedHash1 = sha256(toUtf8Bytes(message1));
    const signer1 = createSign("RSA-SHA256");
    signer1.update(message1);
    signer1.end();
    signature1 = hexlify(signer1.sign(privateKey));

    // Message 2 and Signature
    const message2 = "hey hi";
    expectedHash2 = sha256(toUtf8Bytes(message2));
    const signer2 = createSign("RSA-SHA256");
    signer2.update(message2);
    signer2.end();
    signature2 = hexlify(signer2.sign(privateKey));

    // Extract modulus and exponent
    const { modulus, exponent } = extractModulus_Exponent(publicKey);
    modulusHex = hexlify(modulus);
    exponentHex = hexlify(exponent);
  });

  it("should verify message1 with signature1", async () => {
    const result = await verifier.verifyRSA(
      expectedHash1,
      getBytes(signature1),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );
    expect(result).to.equal(true);
  });

  it("should verify message2 with signature2", async () => {
    const result = await verifier.verifyRSA(
      expectedHash2,
      getBytes(signature2),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );
    expect(result).to.equal(true);
  });

  it("should fail to verify message1 with signature2", async () => {
    const result = await verifier.verifyRSA(
    expectedHash1,
      getBytes(signature2),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );
    expect(result).to.equal(false);
  });

  it("should fail to verify message2 with signature1", async () => {
    const result = await verifier.verifyRSA(
      expectedHash2,
      getBytes(signature1),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );
    expect(result).to.equal(false);
  });
});









