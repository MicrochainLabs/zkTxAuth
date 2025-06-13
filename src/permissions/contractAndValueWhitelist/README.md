
> [!CAUTION]
> This is not proudction ready.
> This is not audited.

> [!WARNING] 
> :warning: Use it at your own risk.

Policy logic development via a ZK program(off-chain programmable permission).

🛡️ ContractValueWhitelistPolicy is a stateless, zero-knowledge circuit for validating whether a user operation complies with pre-established validation rules. It supports native token transfers, ERC20 transfers, and smart contract calls, and ensures all destination addresses are whitelisted via Merkle proofs.

✅ What It Proves
1. Smart contract calls are made only to addresses included in a predefined contract whitelist (via Merkle inclusion proof).

2. Value transfers—either in native tokens or ERC20 tokens—are made only to whitelisted recipient addresses (also verified via Merkle proofs).

Proof generation via node: npx ts-node src/permissions/contractAndValueWhitelist/index.ts

Artifacts generation: proving and verification keys

    1. Create new 'build' and 'build/2_17_17'folders and open new command line inside circuits folder. 

    2. Install circom compiler. More info: https://docs.circom.io/getting-started/installation/

    3. Compile circuit: circom contract_value_whitelist_policy.circom --r1cs --wasm --sym --c -o build/2_17_17

    4. Install snarkjs: yarn add snarkjs.

    5. Run command: snarkjs powersoftau new bn128 15 build/2_17_17/powersOfTau28_hez_final_15.ptau -v 

    6. Run command: snarkjs powersoftau contribute build/2_17_17/powersOfTau28_hez_final_15.ptau build/2_17_17/pot15_0001.ptau --name="First contribution" -v

    7. Run command: snarkjs powersoftau prepare phase2 build/2_17_17/pot15_0001.ptau build/2_17_17/pot15_final.ptau -v

    8. Run command: snarkjs groth16 setup build/2_17_17/contract_value_whitelist_policy.r1cs build/2_17_17/pot15_final.ptau build/2_17_17/contractValueWhitelistPolicy_0000.zkey

    9. Run command: snarkjs zkey contribute build/2_17_17/contractValueWhitelistPolicy_0000.zkey build/2_17_17/contractValueWhitelistPolicy_0001.zkey --name="Second Contributor" -v

    10. contractValueWhitelistPolicy_0001.zkey is the proving key. It is used to generate a ZK proof in the both client or server side.

    11. Export verfication key: snarkjs zkey export verificationkey build/2_17_17/contractValueWhitelistPolicy_0001.zkey build/2_17_17/contractValueWhitelistPolicy_verification_key.json 

    12. Export verfication key in Solidity format: snarkjs zkey export solidityverifier build/2_17_17/contractValueWhitelistPolicy_0001.zkey build/2_17_17/contractValueWhitelistPolicy_verification_key.sol