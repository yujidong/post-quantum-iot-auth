const { ethers } = require("hardhat");

async function main() {
  console.log("Deploying smart contracts...");

  const DIDRegistry = await ethers.getContractFactory("DIDRegistry");
  const didRegistry = await DIDRegistry.deploy();
  await didRegistry.waitForDeployment();
  const didRegistryAddress = await didRegistry.getAddress();
  console.log(`DIDRegistry deployed to: ${didRegistryAddress}`);

  const MetaTxRelay = await ethers.getContractFactory("MetaTxRelay");
  const metaTxRelay = await MetaTxRelay.deploy(didRegistryAddress);
  await metaTxRelay.waitForDeployment();
  const metaTxRelayAddress = await metaTxRelay.getAddress();
  console.log(`MetaTxRelay deployed to: ${metaTxRelayAddress}`);

  console.log("\nDeployment complete.");
  console.log({
    didRegistry: didRegistryAddress,
    metaTxRelay: metaTxRelayAddress,
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
