import { IMT } from "@zk-kit/imt";
import { poseidon2 } from "poseidon-lite";
import { parseEther } from "viem";
// @ts-ignore
import * as snarkjs from 'snarkjs';
import path from "path";
import fs from 'fs';


async function circom(){

    const smartContractCalls = ["0x94D869Ed79067747Be5f160a9566CC79DDc28C3E", "0x337Df693AE75a0ff64317A77dAC8886F61455b85", "0x2CA1d854C83997d56263Bf560A2D198911383b2b"]
    const valueTransfers = ["0xbd8faF57134f9C5584da070cC0be7CA8b5A24953", "0xb9890DC58a1A1a9264cc0E3542093Ee0A1780822", "0x45B52500cb12Ae6046D8566598aB9ccFa7B21aD7"]
    const zeroValue = 0
    const arity = 2
    const whitelistTreeDepth = 17
    const smartContractCallsWhitelistTree = new IMT(poseidon2, whitelistTreeDepth, zeroValue, arity);
    const valueTransfersWhitelistTree = new IMT(poseidon2, whitelistTreeDepth, zeroValue, arity);
     for (let address of smartContractCalls) {
        smartContractCallsWhitelistTree.insert(BigInt(address));
    }

    for (let address of valueTransfers) {
        valueTransfersWhitelistTree.insert(BigInt(address));
    }

    const smartAccount= "0x0F3cB038bA88E5d02364a58e94d8b32f630FE90c";
    const configId = "0x2184431311165abfe4ffc205c316eaf5354177d51288fbcb37b1c31730655cea";
    const stateTreeArity = 2
    const stateTree = new IMT(poseidon2, 2, zeroValue, stateTreeArity);
    stateTree.insert(BigInt(smartAccount))
    stateTree.insert(BigInt(configId))
    stateTree.insert(smartContractCallsWhitelistTree.root)
    stateTree.insert(valueTransfersWhitelistTree.root)

    let op = BigInt("0x127e5d96be61ee1dedb62628c0659e1af3668ae6d255566be3edc5ffd8606574")
    op %= BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")

    const circuitInputs = {
    smartAccount: BigInt(smartAccount),
    configId: BigInt(configId),
    contractWhitelistRoot: smartContractCallsWhitelistTree.root,
    valueWhitelistRoot: valueTransfersWhitelistTree.root,
    userOpHash: op,
    dest:[] as bigint[],
    value: [] as bigint[],
    functionSelector: [] as bigint[], 
    erc20TransferTo:[] as bigint[], 
    nativeCoinTransferSiblings: [] as number[][], 
    nativeCoinTransferIndices: [] as number[][],     
    smartContractCallSiblings: [] as number[][],
    smartContractCallPathIndices: [] as number[][],
    erc20TransferSiblings: [] as number[][],
    erc20TransferPathIndices: [] as number[][] 
  }

  const defaultArray = Array.from({ length: whitelistTreeDepth }, () => 0)

  const txs = [
    {
      dest: BigInt("0xbd8faF57134f9C5584da070cC0be7CA8b5A24953"),//BigInt("0xa564cB165815937967a7d018B7F34B907B52fcFd"),
      value: BigInt(parseEther("0.1")),//BigInt(0),
      functionSelector: BigInt(0),//BigInt(session.actions[0].actionTargetSelector),
      Erc20TransferTo: BigInt(0)
    },
    {
      dest: BigInt(0),
      value: BigInt(0),
      functionSelector: BigInt(0),
      Erc20TransferTo: BigInt(0)
    }
  ]

  for(let tx of txs){
        
    circuitInputs.dest.push(tx.dest)
    circuitInputs.value.push(BigInt(tx.value))
    circuitInputs.functionSelector.push(BigInt(tx.functionSelector))
    circuitInputs.erc20TransferTo.push(BigInt(tx.Erc20TransferTo))
    if(tx.value != BigInt("0x0")){
      const index= valueTransfersWhitelistTree.indexOf(tx.dest);
      const nativeCoinTransferProof=  valueTransfersWhitelistTree.createProof(index);
      circuitInputs.nativeCoinTransferSiblings.push(nativeCoinTransferProof.siblings.map((s) => s[0]))
      circuitInputs.nativeCoinTransferIndices.push(nativeCoinTransferProof.pathIndices)
    }else{
      //static value
      circuitInputs.nativeCoinTransferSiblings.push(defaultArray)
      circuitInputs.nativeCoinTransferIndices.push(defaultArray)
    }

    if(tx.functionSelector != BigInt("0x0")){
      const index= smartContractCallsWhitelistTree.indexOf(tx.dest);
      const smartContractCallProof= smartContractCallsWhitelistTree.createProof(index);
      circuitInputs.smartContractCallSiblings.push(smartContractCallProof.siblings.map((s) => s[0]))
      circuitInputs.smartContractCallPathIndices.push(smartContractCallProof.pathIndices)
    }else{
      circuitInputs.smartContractCallSiblings.push(defaultArray)
      circuitInputs.smartContractCallPathIndices.push(defaultArray)
    }

    if(tx.functionSelector == BigInt("0xa9059cbb") && tx.Erc20TransferTo != BigInt("0x0")){
      const index= valueTransfersWhitelistTree.indexOf(tx.Erc20TransferTo);
      const erc20TransferProof= valueTransfersWhitelistTree.createProof(index);
      circuitInputs.erc20TransferSiblings.push(erc20TransferProof.siblings.map((s) => s[0]))
      circuitInputs.erc20TransferPathIndices.push(erc20TransferProof.pathIndices)
    }else{
      circuitInputs.erc20TransferSiblings.push(defaultArray)
      circuitInputs.erc20TransferPathIndices.push(defaultArray)
    }
  }

  const witnessGenerationPath = path.join(__dirname, 'circuits/circom/build/2_17_17/contract_value_whitelist_policy_js/contract_value_whitelist_policy.wasm');
  const provingKeyPath = path.join(__dirname, 'circuits/circom/build/2_17_17/contractValueWhitelistPolicy_0001.zkey');
  const verificationKeyKeyPath = path.join(__dirname, 'circuits/circom/build/2_17_17/contractValueWhitelistPolicy_verification_key.json');
  const vKey = JSON.parse(fs.readFileSync(verificationKeyKeyPath, "utf-8"));

  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInputs, witnessGenerationPath, provingKeyPath);
  const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
  
  console.log("Public inputs: ", publicSignals)
  console.log("Proof: ", proof)
  console.log("Proof verification: ", res)
}

async function main(){
await circom()
}

main().then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });