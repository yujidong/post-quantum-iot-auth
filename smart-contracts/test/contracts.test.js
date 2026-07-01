const { expect } = require("chai");
const { ethers } = require("hardhat");

// NOTE: Using random bytes as Falcon-512 key/signature stand-ins.
// Real Falcon-512 keys are exactly 897 bytes with specific internal structure.
// Gas measurements are unaffected since on-chain logic does not parse key internals.
const FALCON_PK_SIZE = 897;
const FALCON_SIG_SIZE = 752;

describe("DIDRegistry", function () {
  let didRegistry;
  let owner, addr1, addr2;

  const falconPublicKey = ethers.randomBytes(FALCON_PK_SIZE);

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
    didRegistry = await DIDRegistry.deploy();
  });

  describe("DID Registration", function () {
    it("should register a new DID with correct event parameters", async function () {
      const didHash = ethers.id("did:falconiot:device001");
      await expect(
        didRegistry.connect(addr1).registerDID(didHash, falconPublicKey)
      ).to.emit(didRegistry, "DIDRegistered")
       .withArgs(didHash, addr1.address, (await ethers.provider.getBlock("latest")).timestamp + 1);

      const doc = await didRegistry.dids(didHash);
      expect(doc.owner).to.equal(addr1.address);
      expect(doc.active).to.be.true;
    });

    it("should store the public key correctly", async function () {
      const didHash = ethers.id("did:falconiot:device002");
      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);

      const storedKey = await didRegistry.getPublicKey(didHash);
      expect(storedKey).to.equal(ethers.hexlify(falconPublicKey));
    });

    it("should reject duplicate DID registration", async function () {
      const didHash = ethers.id("did:falconiot:device003");
      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);

      await expect(
        didRegistry.connect(addr2).registerDID(didHash, falconPublicKey)
      ).to.be.revertedWith("DID already exists");
    });

    it("should reject wrong-sized public key", async function () {
      const didHash = ethers.id("did:falconiot:device-bad-key");
      const wrongKey = ethers.randomBytes(64); // ECDSA-sized, not Falcon

      await expect(
        didRegistry.connect(addr1).registerDID(didHash, wrongKey)
      ).to.be.revertedWith("Invalid public key length");
    });

    it("should record timestamp", async function () {
      const didHash = ethers.id("did:falconiot:device004");
      const tx = await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);
      const receipt = await tx.getBlock();

      const doc = await didRegistry.dids(didHash);
      expect(doc.registeredAt).to.equal(receipt.timestamp);
    });

    it("should report isActive correctly", async function () {
      const didHash = ethers.id("did:falconiot:device-active");
      expect(await didRegistry.isActive(didHash)).to.be.false;

      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);
      expect(await didRegistry.isActive(didHash)).to.be.true;
    });
  });

  describe("DID Deactivation", function () {
    it("should allow owner to deactivate with correct event", async function () {
      const didHash = ethers.id("did:falconiot:device005");
      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);

      await expect(
        didRegistry.connect(addr1).deactivateDID(didHash)
      ).to.emit(didRegistry, "DIDDeactivated");

      const doc = await didRegistry.dids(didHash);
      expect(doc.active).to.be.false;
      expect(await didRegistry.isActive(didHash)).to.be.false;
    });

    it("should reject deactivation by non-owner", async function () {
      const didHash = ethers.id("did:falconiot:device006");
      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);

      await expect(
        didRegistry.connect(addr2).deactivateDID(didHash)
      ).to.be.revertedWith("Not owner");
    });

    it("should reject double deactivation", async function () {
      const didHash = ethers.id("did:falconiot:device-dbl-deact");
      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);
      await didRegistry.connect(addr1).deactivateDID(didHash);

      await expect(
        didRegistry.connect(addr1).deactivateDID(didHash)
      ).to.be.revertedWith("DID already deactivated");
    });

    it("should revert getPublicKey for deactivated DID", async function () {
      const didHash = ethers.id("did:falconiot:device-deact-pk");
      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);
      await didRegistry.connect(addr1).deactivateDID(didHash);

      await expect(
        didRegistry.getPublicKey(didHash)
      ).to.be.revertedWith("DID is deactivated");
    });
  });

  describe("Gas Measurements", function () {
    it("should measure DID registration gas cost", async function () {
      const didHash = ethers.id("did:falconiot:gas-test");
      const tx = await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);
      const receipt = await tx.wait();
      console.log(`      DID registration gas: ${receipt.gasUsed.toString()}`);
      // Falcon-512 public key is 897 bytes, so storage cost is higher than typical keys
      expect(receipt.gasUsed).to.be.lt(1000000);
    });

    it("should measure public key lookup gas cost", async function () {
      const didHash = ethers.id("did:falconiot:lookup-test");
      await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);

      const gasEstimate = await didRegistry.getPublicKey.estimateGas(didHash);
      console.log(`      Public key lookup gas: ${gasEstimate.toString()}`);
      // Reading 897-byte Falcon public key from storage costs more than typical keys
      expect(gasEstimate).to.be.lt(100000);
    });
  });
});

describe("MetaTxRelay", function () {
  let metaTxRelay, didRegistry;
  let owner, relay, addr1, addr2;

  const falconPublicKey = ethers.randomBytes(FALCON_PK_SIZE);
  const falconSignature = ethers.randomBytes(FALCON_SIG_SIZE);

  beforeEach(async function () {
    [owner, relay, addr1, addr2] = await ethers.getSigners();

    const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
    didRegistry = await DIDRegistry.deploy();

    const MetaTxRelay = await ethers.getContractFactory("MetaTxRelay");
    metaTxRelay = await MetaTxRelay.deploy(await didRegistry.getAddress());
  });

  // Helper: register a DID for use in relay tests
  async function registerTestDid(label) {
    const didHash = ethers.id(`did:falconiot:${label}`);
    await didRegistry.connect(addr1).registerDID(didHash, falconPublicKey);
    return didHash;
  }

  describe("Transaction Submission", function () {
    it("should submit a relay-assisted transaction", async function () {
      const didHash = await registerTestDid("relay-device");

      const dataHash = ethers.id("sensor-data-payload");
      const tx = await metaTxRelay
        .connect(relay)
        .submitTransaction(dataHash, didHash, falconSignature, true);

      await expect(tx).to.emit(metaTxRelay, "TransactionSubmitted");
    });

    it("should reject submission with unregistered DID", async function () {
      const dataHash = ethers.id("sensor-data-payload");
      const fakeDidHash = ethers.id("did:falconiot:nonexistent");

      await expect(
        metaTxRelay.connect(relay).submitTransaction(dataHash, fakeDidHash, falconSignature, true)
      ).to.be.revertedWith("DID not active");
    });

    it("should reject submission with deactivated DID", async function () {
      const didHash = await registerTestDid("deact-relay");
      await didRegistry.connect(addr1).deactivateDID(didHash);

      const dataHash = ethers.id("deact-data");
      await expect(
        metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, falconSignature, true)
      ).to.be.revertedWith("DID not active");
    });

    it("should reject wrong-sized signature", async function () {
      const didHash = await registerTestDid("relay-bad-sig");
      const dataHash = ethers.id("bad-sig-data");

      // Empty signature should be rejected
      await expect(
        metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, "0x", true)
      ).to.be.revertedWith("Invalid signature length");

      // Signature exceeding max size should be rejected
      const tooLargeSig = ethers.randomBytes(FALCON_SIG_SIZE + 1);
      await expect(
        metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, tooLargeSig, true)
      ).to.be.revertedWith("Invalid signature length");
    });

    it("should reject replay of identical transaction", async function () {
      const didHash = await registerTestDid("replay-device");

      const dataHash = ethers.id("replay-data");
      await metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, falconSignature, true);

      // Same (dataHash, didHash, signature) should be rejected
      await expect(
        metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, falconSignature, true)
      ).to.be.revertedWith("Replay: already submitted");
    });

    it("should increment transaction count", async function () {
      const didHash = await registerTestDid("counter-device");

      expect(await metaTxRelay.transactionCount()).to.equal(0);

      const dataHash = ethers.id("data-1");
      await metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, falconSignature, true);
      expect(await metaTxRelay.transactionCount()).to.equal(1);

      // Use different data hash + signature for second tx (replay protection)
      const dataHash2 = ethers.id("data-2");
      const sig2 = ethers.randomBytes(FALCON_SIG_SIZE);
      await metaTxRelay.connect(relay).submitTransaction(dataHash2, didHash, sig2, true);
      expect(await metaTxRelay.transactionCount()).to.equal(2);
    });
  });

  describe("Transaction Retrieval", function () {
    it("should retrieve stored transaction for offline verification", async function () {
      const didHash = await registerTestDid("retrieve-device");

      const dataHash = ethers.id("retrieve-test-data");
      await metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, falconSignature, true);

      const count = await metaTxRelay.transactionCount();
      expect(count).to.equal(1);

      const [retDataHash, retDidHash, retSig, retPubKeyHash] =
        await metaTxRelay.getTransactionForVerification(0);

      expect(retDataHash).to.equal(dataHash);
      expect(retDidHash).to.equal(didHash);
      expect(retSig).to.equal(ethers.hexlify(falconSignature));

      // Verify the stored public key hash matches the actual public key
      const expectedPubKeyHash = ethers.keccak256(falconPublicKey);
      expect(retPubKeyHash).to.equal(expectedPubKeyHash);
    });

    it("should revert on out-of-bounds transaction index", async function () {
      await expect(
        metaTxRelay.getTransactionForVerification(0)
      ).to.be.reverted;

      // Also test after a transaction exists
      const didHash = await registerTestDid("oob-test");
      const dataHash = ethers.id("oob-data");
      await metaTxRelay.connect(relay).submitTransaction(dataHash, didHash, falconSignature, true);

      await expect(
        metaTxRelay.getTransactionForVerification(1)
      ).to.be.reverted;
    });
  });

  describe("Verification Results", function () {
    it("should store failed verification result", async function () {
      const didHash = await registerTestDid("fail-device");
      const dataHash = ethers.id("fail-data");

      await metaTxRelay
        .connect(relay)
        .submitTransaction(dataHash, didHash, falconSignature, false);

      const txData = await metaTxRelay.transactions(0);
      expect(txData.verified).to.be.false;
    });
  });

  describe("Gas Measurements", function () {
    it("should measure relay transaction gas cost", async function () {
      const didHash = await registerTestDid("gas-relay");

      const dataHash = ethers.id("gas-test-data");
      const tx = await metaTxRelay
        .connect(relay)
        .submitTransaction(dataHash, didHash, falconSignature, true);
      const receipt = await tx.wait();
      console.log(`      Relay transaction gas: ${receipt.gasUsed.toString()}`);
    });

    it("relay gas should be far less than theoretical on-chain Falcon", async function () {
      const didHash = await registerTestDid("comparison");

      const dataHash = ethers.id("comparison-data");
      const tx = await metaTxRelay
        .connect(relay)
        .submitTransaction(dataHash, didHash, falconSignature, true);
      const receipt = await tx.wait();
      const relayGas = receipt.gasUsed;

      console.log(`      Relay gas: ${relayGas.toString()}`);
      console.log(`      Theoretical Falcon on-chain: ~500,000,000`);
      console.log(`      Ratio: ${(500000000n / relayGas).toString()}x reduction`);
      expect(relayGas).to.be.lt(1000000);
    });
  });
});

describe("ECDSAVerify", function () {
  let ecdsaVerify;
  let owner, addr1;
  let testWallet;

  beforeEach(async function () {
    [owner, addr1] = await ethers.getSigners();
    const ECDSAVerify = await ethers.getContractFactory("ECDSAVerify");
    ecdsaVerify = await ECDSAVerify.deploy();

    // Create a wallet with known key for raw hash signing
    testWallet = ethers.Wallet.createRandom();
  });

  describe("Signature Verification", function () {
    it("should verify a valid ECDSA signature (raw hash)", async function () {
      const dataHash = ethers.id("test-data-payload");

      // Sign the raw hash (no EIP-191 prefix) using the wallet's signing key
      const sig = testWallet.signingKey.sign(dataHash);
      const v = sig.v;
      const r = sig.r;
      const s = sig.s;

      await expect(
        ecdsaVerify.submitAndVerify(dataHash, v, r, s)
      ).to.emit(ecdsaVerify, "DataVerified");

      expect(await ecdsaVerify.latestDataHash()).to.equal(dataHash);
      expect(await ecdsaVerify.latestSigner()).to.equal(testWallet.address);
    });

    it("should measure ECDSA verification gas cost", async function () {
      const dataHash = ethers.id("gas-test-data");
      const sig = testWallet.signingKey.sign(dataHash);

      const tx = await ecdsaVerify.submitAndVerify(
        dataHash, sig.v, sig.r, sig.s
      );
      const receipt = await tx.wait();
      console.log(`      ECDSA verify gas: ${receipt.gasUsed.toString()}`);
      // ecrecover + SSTORE + event should be ~35K gas
      expect(receipt.gasUsed).to.be.gt(20000);
      expect(receipt.gasUsed).to.be.lt(100000);
    });
  });

  describe("ECDSA with Signature Storage", function () {
    it("should store full ECDSA signature on-chain", async function () {
      const dataHash = ethers.id("store-sig-data");
      const sig = testWallet.signingKey.sign(dataHash);

      await expect(
        ecdsaVerify.submitVerifyAndStore(dataHash, sig.v, sig.r, sig.s)
      ).to.emit(ecdsaVerify, "DataVerifiedWithSig");

      expect(await ecdsaVerify.latestDataHash()).to.equal(dataHash);
      expect(await ecdsaVerify.latestSigner()).to.equal(testWallet.address);
      expect(await ecdsaVerify.latestSigR()).to.equal(sig.r);
      expect(await ecdsaVerify.latestSigS()).to.equal(sig.s);
    });

    it("should measure ECDSA verify+store gas cost", async function () {
      const dataHash = ethers.id("store-gas-data");
      const sig = testWallet.signingKey.sign(dataHash);

      const tx = await ecdsaVerify.submitVerifyAndStore(
        dataHash, sig.v, sig.r, sig.s
      );
      const receipt = await tx.wait();
      console.log(`      ECDSA verify+store gas: ${receipt.gasUsed.toString()}`);
      // ecrecover + SSTORE (dataHash + signer + sigR + sigS) + event
      expect(receipt.gasUsed).to.be.gt(35000);
      expect(receipt.gasUsed).to.be.lt(150000);
    });
  });

  describe("Signer Verification", function () {
    it("should accept any signer when verification disabled", async function () {
      const dataHash = ethers.id("open-signer-data");
      const sig = testWallet.signingKey.sign(dataHash);

      // Default: verification disabled, any signer accepted
      await expect(
        ecdsaVerify.submitAndVerify(dataHash, sig.v, sig.r, sig.s)
      ).to.emit(ecdsaVerify, "DataVerified");
    });

    it("should reject unregistered signer when verification enabled", async function () {
      // Enable signer verification
      await ecdsaVerify.setSignerVerification(true);

      const dataHash = ethers.id("restricted-signer-data");
      const sig = testWallet.signingKey.sign(dataHash);

      await expect(
        ecdsaVerify.submitAndVerify(dataHash, sig.v, sig.r, sig.s)
      ).to.be.revertedWith("Signer not registered");
    });

    it("should accept registered signer when verification enabled", async function () {
      // Register the test wallet, then enable verification
      await ecdsaVerify.registerSigner(testWallet.address);
      await ecdsaVerify.setSignerVerification(true);

      const dataHash = ethers.id("registered-signer-data");
      const sig = testWallet.signingKey.sign(dataHash);

      await expect(
        ecdsaVerify.submitAndVerify(dataHash, sig.v, sig.r, sig.s)
      ).to.emit(ecdsaVerify, "DataVerified");
      expect(await ecdsaVerify.latestSigner()).to.equal(testWallet.address);
    });

    it("should apply signer verification to submitVerifyAndStore", async function () {
      await ecdsaVerify.registerSigner(testWallet.address);
      await ecdsaVerify.setSignerVerification(true);

      const dataHash = ethers.id("store-verify-signer-data");
      const sig = testWallet.signingKey.sign(dataHash);

      await expect(
        ecdsaVerify.submitVerifyAndStore(dataHash, sig.v, sig.r, sig.s)
      ).to.emit(ecdsaVerify, "DataVerifiedWithSig");
    });
  });
});
