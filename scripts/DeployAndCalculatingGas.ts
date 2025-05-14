import { ethers } from "hardhat";
import { generateKeyPairSync, createSign } from "crypto";
import { sha256 } from "@ethersproject/sha2";
import { toUtf8Bytes } from "@ethersproject/strings";
import { arrayify as getBytes, hexlify } from "@ethersproject/bytes";
import * as asn1 from "asn1.js";

async function main() {
  // ASN.1 RSAPublicKey structure to decode the PEM
  const RSAPublicKeyASN = asn1.define("RSAPublicKey", function (this: any) {
    this.seq().obj(
      this.key("n").int(), // modulus
      this.key("e").int()  // exponent
    );
  });

  // Helper function to extract modulus and exponent from PEM
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

  // Deploy contracts
  const RSAVerifierOPZep = await ethers.getContractFactory("RSAVerifierOPZep");
  const verifier = await RSAVerifierOPZep.deploy();
  await verifier.waitForDeployment();

  const RSAVerifierCusLib = await ethers.getContractFactory("RSAVerifierCusLib");
  const verifier1 = await RSAVerifierCusLib.deploy();
  await verifier1.waitForDeployment();

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

  // Prepare message and hash
  const message = "hi man";
  const expectedHash = sha256(toUtf8Bytes(message));

  const signer = createSign("RSA-SHA256");
  signer.update(message);
  signer.end();
  const signatureBuffer = signer.sign(privateKey);
  const signature = hexlify(signatureBuffer);

  // Extract key parts
  const { modulusHex, exponentHex } = extractModulusExponentFromPem(publicKey);

  // Call contracts
  const tx = await verifier.testGas(
    expectedHash,
    getBytes(signature),
    getBytes(exponentHex),
    getBytes(modulusHex)
  );
  const receipt = await tx.wait();

  const tx1 = await verifier1.testGas(
    getBytes(signature),
    expectedHash,
    getBytes(modulusHex),
    getBytes(exponentHex)
    
  );
  const receipt1 = await tx.wait();



  // Parse logs using contracts interface
  
  const iface = verifier.interface;
  for (const log of receipt.logs) {
    try {
      const parsedLog = iface.parseLog(log);
      if (parsedLog.name === "GasUsed") {
        console.log("Gas Used With Using OpenZeppelin Library:", parsedLog.args.gasUsed.toString());
      }
    } catch (err) {
      continue;
    }
  }

  const iface1 = verifier1.interface;
  for (const log of receipt1.logs) {
    try {
      const parsedLog = iface1.parseLog(log);
      if (parsedLog.name === "GasUsed") {
        console.log("Gas Used with using custom library:", parsedLog.args.gasUsed.toString());
      }
    } catch (err) {
      continue;
    }
  }
}

main().catch(console.error);

