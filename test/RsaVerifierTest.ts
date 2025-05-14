import { expect } from "chai";
import { ethers } from "hardhat";
import { generateKeyPairSync, createSign } from "crypto";
import { sha256 } from "@ethersproject/sha2";
import { toUtf8Bytes } from "@ethersproject/strings";
import { arrayify as getBytes, hexlify } from "@ethersproject/bytes";
import * as asn1 from "asn1.js";

describe("RSAVerifier", function () {
  let verifier: any;

  // ASN.1 RSAPublicKey structure to decode the PEM
  const RSAPublicKeyASN = asn1.define("RSAPublicKey", function (this: any) {
    this.seq().obj(
      this.key("n").int(), // modulus
      this.key("e").int()  // exponent
    );
  });

  // Helper function to convert PEM public key to modulus and exponent hex
  function extractModulusExponentFromPem(pem: string): {
    modulusHex: string;
    exponentHex: string;
  } {
    
    //clears out the header, footer, and whitespace from the PEM key
    const pemBody = pem
      .replace("-----BEGIN RSA PUBLIC KEY-----", "")  
      .replace("-----END RSA PUBLIC KEY-----", "")
      .replace(/\s+/g, "");

    const der = Buffer.from(pemBody, "base64");
    const decoded = RSAPublicKeyASN.decode(der, "der");

    const modulusHex = hexlify(decoded.n.toBuffer());
    const exponentHex = hexlify(decoded.e.toBuffer());

    return { modulusHex, exponentHex };
  }

  before(async () => {
    const RSAVerifierFactory = await ethers.getContractFactory("RSAVerifierOPZep");
    verifier = await RSAVerifierFactory.deploy();
    await verifier.waitForDeployment();
  });

  it("should verify a valid RSA signature", async () => {
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

    const message = "hi man";
    const expectedHash = sha256(toUtf8Bytes(message));

    const signer = createSign("RSA-SHA256");
    signer.update(message);
    signer.end();
    const signatureBuffer = signer.sign(privateKey);
    const signature = hexlify(signatureBuffer);

    const { modulusHex, exponentHex } = extractModulusExponentFromPem(publicKey);

    const result = await verifier.verifyRSA(
      expectedHash,
      getBytes(signature),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );

    expect(result).to.equal(true);
  });

  it("should fail when passing the wrong expectedHash", async () => {
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

    const message = "hi man";
    const expectedHash = sha256(toUtf8Bytes(message));

    const signer = createSign("RSA-SHA256");
    signer.update(message);
    signer.end();
    const signatureBuffer = signer.sign(privateKey);
    const signature = hexlify(signatureBuffer);

    const { modulusHex, exponentHex } = extractModulusExponentFromPem(publicKey);

    const wrongExpectedHash = sha256(toUtf8Bytes("hello")); // hash for other message

    const result = await verifier.verifyRSA(
      wrongExpectedHash,
      getBytes(signature),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );

    expect(result).to.equal(false);
  });
});

describe("RsaTwoMessagesVerifier", function () {
  let verifier: any;

  // ASN.1 RSAPublicKey structure to decode the PEM
  const RSAPublicKeyASN = asn1.define("RSAPublicKey", function (this: any) {
    this.seq().obj(
      this.key("n").int(), // modulus
      this.key("e").int()  // exponent
    );
  });

  // Helper function to convert PEM public key to modulus and exponent hex
  function extractModulusExponentFromPem(pem: string): {
    modulusHex: string;
    exponentHex: string;
  } {
    const pemBody = pem
      .replace("-----BEGIN RSA PUBLIC KEY-----", "")
      .replace("-----END RSA PUBLIC KEY-----", "")
      .replace(/\s+/g, "");

    const der = Buffer.from(pemBody, "base64");
    const decoded = RSAPublicKeyASN.decode(der, "der");

    const modulusHex = hexlify(decoded.n.toBuffer());
    const exponentHex = hexlify(decoded.e.toBuffer());

    return { modulusHex, exponentHex };
  }

  before(async () => {
    const RSAVerifierFactory = await ethers.getContractFactory("RSAVerifierOPZep");
    verifier = await RSAVerifierFactory.deploy();
    await verifier.waitForDeployment();
  });

  it("should verify multiple messages with their respective signatures and fail if it's not their signatures", async () => {
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

    const { modulusHex, exponentHex } = extractModulusExponentFromPem(publicKey);

    // Message 1
    const message1 = "hey hello";
    const expectedHash1 = sha256(toUtf8Bytes(message1));
    const signer1 = createSign("RSA-SHA256");
    signer1.update(message1);
    signer1.end();
    const signature1 = hexlify(signer1.sign(privateKey));

    // Message 2
    const message2 = "hey hi";
    const expectedHash2 = sha256(toUtf8Bytes(message2));
    const signer2 = createSign("RSA-SHA256");
    signer2.update(message2);
    signer2.end();
    const signature2 = hexlify(signer2.sign(privateKey));

    // Verify message1 with signature1
    const result1 = await verifier.verifyRSA(
      expectedHash1,
      getBytes(signature1),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );

    expect(result1).to.equal(true);

    // Verify message2 with signature2
    const result2 = await verifier.verifyRSA(
      expectedHash2,
      getBytes(signature2),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );

    expect(result2).to.equal(true);

    // Verify message1 with signature2 should fail
    const result3 = await verifier.verifyRSA(
      expectedHash1,
      getBytes(signature2),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );
    expect(result3).to.equal(false);

    // Verify message2 with signature1 should fail
    const result4 = await verifier.verifyRSA(
      expectedHash2,
      getBytes(signature1),
      getBytes(exponentHex),
      getBytes(modulusHex)
    );
    expect(result4).to.equal(false);
  });
});










