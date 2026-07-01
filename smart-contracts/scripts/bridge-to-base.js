const { ethers } = require("ethers");
require("dotenv").config();

/**
 * Bridge ETH from Sepolia L1 to Base Sepolia L2.
 * Uses L1StandardBridge (proxy) on Sepolia.
 */
async function main() {
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
  const wallet = new ethers.Wallet(process.env.PRIVATE_KEY_1, provider);

  const BRIDGE = "0xfd0Bf71F60660E2f608ed56e1659C450eB113120";
  const iface = new ethers.Interface([
    "function depositETHTo(address _to, uint32 _minGasLimit, bytes _data) external payable"
  ]);

  const balance = await provider.getBalance(wallet.address);
  console.log(`Account: ${wallet.address}`);
  console.log(`Balance: ${ethers.formatEther(balance)} ETH`);

  const amount = ethers.parseEther("0.3");
  const calldata = iface.encodeFunctionData("depositETHTo", [
    wallet.address,   // recipient on L2
    200000,           // minGasLimit
    "0x"              // extra data
  ]);

  console.log(`Bridging ${ethers.formatEther(amount)} ETH to Base Sepolia...`);

  // Estimate gas first
  try {
    await provider.estimateGas({
      from: wallet.address,
      to: BRIDGE,
      data: calldata,
      value: amount
    });
    console.log("Gas estimation OK");
  } catch(e) {
    console.log("Gas estimation failed, trying with explicit gas limit...");
    console.log(`  Error: ${e.message.substring(0, 100)}`);
  }

  const tx = await wallet.sendTransaction({
    to: BRIDGE,
    data: calldata,
    value: amount,
    gasLimit: 500000
  });

  console.log(`Tx: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`Status: ${receipt.status === 1 ? "SUCCESS" : "REVERTED"}`);
  console.log(`Block: ${receipt.blockNumber}, Gas: ${receipt.gasUsed}`);
  console.log(`\nCheck Base Sepolia balance in 1-5 min:`);
  console.log(`  https://sepolia.basescan.org/address/${wallet.address}`);
}

main().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
