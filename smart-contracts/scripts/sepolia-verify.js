const { ethers } = require("hardhat");

/**
 * Sepolia verification script.
 * Deploys contracts, registers a DID, submits a relay transaction,
 * and reports gas costs to compare with local Hardhat results.
 *
 * Usage: npx hardhat run scripts/sepolia-verify.js --network sepolia
 */
async function main() {
  const [deployer] = await ethers.getSigners();
  const balance = await ethers.provider.getBalance(deployer.address);
  console.log("=== Sepolia Verification ===");
  console.log(`Account: ${deployer.address}`);
  console.log(`Balance: ${ethers.formatEther(balance)} ETH`);
  console.log("");

  // --- 1. Deploy DIDRegistry ---
  console.log("Deploying DIDRegistry...");
  const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();
  const didAddr = await didRegistry.getAddress();
  const deployTx = await didRegistry.deploymentTransaction();
  const deployReceipt = await deployTx.wait();
  console.log(`  Address: ${didAddr}`);
  console.log(`  Deploy gas: ${deployReceipt.gasUsed.toString()}`);
  console.log("");

  // --- 2. Deploy MetaTxRelay ---
  console.log("Deploying MetaTxRelay...");
  const MetaTxRelay = await ethers.getContractFactory("MetaTxRelay");
  const metaTxRelay = await MetaTxRelay.deploy(didAddr);
  await metaTxRelay.waitForDeployment();
  const relayAddr = await metaTxRelay.getAddress();
  const relayDeployReceipt = await metaTxRelay.deploymentTransaction().wait();
  console.log(`  Address: ${relayAddr}`);
  console.log(`  Deploy gas: ${relayDeployReceipt.gasUsed.toString()}`);
  console.log("");

  // --- 3. Register a DID ---
  console.log("Registering a DID...");
  const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:test:iot-device-001"));
  // Generate a dummy 897-byte Falcon-512 public key
  const falconPk = ethers.randomBytes(897);
  const regTx = await didRegistry.registerDID(didHash, falconPk);
  const regReceipt = await regTx.wait();
  console.log(`  DID: ${didHash}`);
  console.log(`  Register gas: ${regReceipt.gasUsed.toString()}`);
  console.log("");

  // --- 4. Submit a relay transaction ---
  console.log("Submitting relay transaction...");
  const dataHash = ethers.keccak256(ethers.toUtf8Bytes("temperature=23.5&humidity=45"));
  // Generate a dummy Falcon-512 signature (random bytes within valid size range)
  const falconSig = ethers.randomBytes(666);
  const submitTx = await metaTxRelay.submitTransaction(dataHash, didHash, falconSig, true);
  const submitReceipt = await submitTx.wait();
  console.log(`  Tx hash: ${submitTx.hash}`);
  console.log(`  Relay tx gas: ${submitReceipt.gasUsed.toString()}`);
  console.log("");

  // --- 5. Retrieve the transaction ---
  console.log("Retrieving transaction for verification...");
  const result = await metaTxRelay.getTransactionForVerification(0);
  console.log(`  Data hash: ${result[0]}`);
  console.log(`  DID hash: ${result[1]}`);
  console.log(`  Signature length: ${result[2].length} bytes`);
  console.log(`  PubKey hash: ${result[3]}`);
  console.log("");

  // --- 6. Public key lookup ---
  console.log("Public key lookup...");
  const lookupTx = await didRegistry.getPublicKey.staticCall(didHash);
  console.log(`  Public key length: ${lookupTx.length} bytes`);
  console.log("");

  // --- 7. Summary ---
  console.log("=== Gas Cost Summary (Sepolia) ===");
  console.log(`DIDRegistry deploy:    ${deployReceipt.gasUsed.toString()}`);
  console.log(`MetaTxRelay deploy:    ${relayDeployReceipt.gasUsed.toString()}`);
  console.log(`DID Registration:      ${regReceipt.gasUsed.toString()}`);
  console.log(`Relay Transaction:     ${submitReceipt.gasUsed.toString()}`);
  console.log("");
  console.log(`Block number: ${submitReceipt.blockNumber}`);
  console.log(`Contract addresses:`);
  console.log(`  DIDRegistry: ${didAddr}`);
  console.log(`  MetaTxRelay: ${relayAddr}`);
  console.log("");
  console.log("Sepolia verification complete.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
