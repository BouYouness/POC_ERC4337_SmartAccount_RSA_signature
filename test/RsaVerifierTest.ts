import { expect } from "chai";
import { ethers } from "hardhat";
import { execSync } from "child_process";
import { sha256 } from "@ethersproject/sha2";
import { toUtf8Bytes } from "@ethersproject/strings";
import { getBytes } from "ethers";

describe("RSAVerifier", function () {
  let verifier: any;

  let rsaValues: {
    signature: string;
    modulus: string;
    exponent: string;
    expectedHash: string;
  };

  function parseRSAOutput(output: string): {
    signature: string;
    modulus: string;
    exponent: string;
    expectedHash: string;
  } {
    const lines = output.trim().split("\n");
    const result: { [key: string]: string } = {};
    for (const line of lines) {
      const [key, value] = line.split("=");
      if (key && value) {
        result[key.trim()] = value.trim();
      }
    }
    return {
      signature: result.signature,
      modulus: result.modulus,
      exponent: result.exponent,
      expectedHash: result.expectedHash,
    };
  }

  before(async () => {
    const RSAVerifierFactory = await ethers.getContractFactory("RSAVerifier");
    verifier = await RSAVerifierFactory.deploy();
    await verifier.waitForDeployment();

    const outputBuffer = execSync("./scripts/generate_rsa_values.sh", { shell: "bash" });
    const outputString = outputBuffer.toString();
    rsaValues = parseRSAOutput(outputString);

    if (
      !rsaValues.signature ||
      !rsaValues.modulus ||
      !rsaValues.exponent ||
      !rsaValues.expectedHash
    ) {
      throw new Error("Missing RSA values from script output");
    }
  });

  it("should verify a valid RSA signature", async () => {
    const { signature, exponent, modulus, expectedHash } = rsaValues;

    const result = await verifier.verifyRSA(
      getBytes(signature),   // hex string to bytes
      expectedHash,          
      getBytes(modulus),     // hex string to bytes
      getBytes(exponent)     // hex string to bytes
    );

    expect(result).to.equal(true);
  });

  /**
  * @notice Signature and key pairs are generated for specific message but we passed expectedHash for another message so verify of valid message should fail
  */

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



