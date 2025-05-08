import { expect } from "chai";
import { ethers } from "hardhat";
import { sha256 } from "@ethersproject/sha2";
import { toUtf8Bytes } from "@ethersproject/strings";
import { RSAVerifier } from "../contracts/RSAVerifier.sol";

describe("RSAVerifier", function () {

 
  /**
  * @notice Signature and key pairs are already generated, generate yours using generate_rsa_values.sh for your specific message before testing.
  * @param modulus The RSA modulus part of the public key.
  * @param exponent The RSA exponent part of the public key.
  * @param signature The RSA signature.
  */

  let verifier: RSAVerifier;

  before(async () => {
    const RSAVerifierFactory = await ethers.getContractFactory("RSAVerifier");
    verifier = await RSAVerifierFactory.deploy();
    await verifier.waitForDeployment();
  });

  it("should verify a valid RSA signature", async () => {
    const signature = "0x7ad537270a470f1711aa67961e4a27bbb282b7098d77d1cb88430b96081723a2acd53d8e0969f9efb1ab5a1a91b8ef6e62f2b46e02848f16c4e9f2270dd6449f62555a5866d59c3330e2cf594a732e17695744ea0076ba1c068a426d0513f67032b519d4eacafa9a0a1ebcd3a438ccb5dc95c263481f370c3b1edb4b33c4c387060ffbe1a0f617ff0e9ec64fa7872357394b51c7ef19f6598ed4f0b0d6cc36e564866c12033632ff11126ccc188f216aa6dab1f1750d8c8ccf44b4b6dde2ef08c483087c8f4088110bfe567804fd2052c3e1fd4af6281f28873ae224ae091ec2d49790a55c01536a96765a91fc27ce37a1b9d45f6a81234b4561029ad2dab577";
    const modulus = "0x00a37a4f654b106c0af6c010e6e214f56c38e515206ac0d7b009c47380c66589703a5f4a63893561c438b2a7bbd65e9a2ad5454d5ad146c02668e67683bc38626b6c503d77041fa28884579afb10ae3d229e3f648e0c0895ad1e6c4373b42c32fa92cbba15121e63fb91261acf1696a83d757d05faecdbbc9fd352e833ac9f6c0b2df0467bb3ac89676f7521d638f292bc410d2e57a186ad89b16243d66d8ff9f3dc871a343ecd55ba7a404efec30637949b6d3c3094da3a08f0fa23c56c8fe5398b4d507c0f731ffa30872dd038e5f51e2c5157f6c759f930b0e64ca2bbbf932faa89c447c54b715dac0eb0c6a96524cc90944e73de37ad1b2f920ca08841b779";
    const exponent = "0x010001"; // 65537
    const expectedHash = sha256(toUtf8Bytes("how you doing?"));

    const result = await verifier.verifyRSA(
      signature,
      expectedHash,
      modulus,
      exponent
    );

    expect(result).to.equal(true);
  });
   

  /**
  * @notice Signature and key pairs are generated for specific message but we passed expectedHash for another message so verify of valid message should fail
  */
  it("should fall after passing wrong expectedHash", async () => {
    const signature = "0x7ad537270a470f1711aa67961e4a27bbb282b7098d77d1cb88430b96081723a2acd53d8e0969f9efb1ab5a1a91b8ef6e62f2b46e02848f16c4e9f2270dd6449f62555a5866d59c3330e2cf594a732e17695744ea0076ba1c068a426d0513f67032b519d4eacafa9a0a1ebcd3a438ccb5dc95c263481f370c3b1edb4b33c4c387060ffbe1a0f617ff0e9ec64fa7872357394b51c7ef19f6598ed4f0b0d6cc36e564866c12033632ff11126ccc188f216aa6dab1f1750d8c8ccf44b4b6dde2ef08c483087c8f4088110bfe567804fd2052c3e1fd4af6281f28873ae224ae091ec2d49790a55c01536a96765a91fc27ce37a1b9d45f6a81234b4561029ad2dab577";
    const modulus = "0x00a37a4f654b106c0af6c010e6e214f56c38e515206ac0d7b009c47380c66589703a5f4a63893561c438b2a7bbd65e9a2ad5454d5ad146c02668e67683bc38626b6c503d77041fa28884579afb10ae3d229e3f648e0c0895ad1e6c4373b42c32fa92cbba15121e63fb91261acf1696a83d757d05faecdbbc9fd352e833ac9f6c0b2df0467bb3ac89676f7521d638f292bc410d2e57a186ad89b16243d66d8ff9f3dc871a343ecd55ba7a404efec30637949b6d3c3094da3a08f0fa23c56c8fe5398b4d507c0f731ffa30872dd038e5f51e2c5157f6c759f930b0e64ca2bbbf932faa89c447c54b715dac0eb0c6a96524cc90944e73de37ad1b2f920ca08841b779";
    const exponent = "0x010001"; // 65537
    const expectedHash = sha256(toUtf8Bytes("hello"));

    const result = await verifier.verifyRSA(
      signature,
      expectedHash,
      modulus,
      exponent
    );

    expect(result).to.equal(false);
  });
});
