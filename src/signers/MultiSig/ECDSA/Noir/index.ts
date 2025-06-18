


import circuit from './target/noir.json';
import { Noir } from '@noir-lang/noir_js';
import { ethers, hashMessage, toBeHex } from "ethers";

import { IMT } from '@zk-kit/imt';
import { poseidon1, poseidon2 } from "poseidon-lite";
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { Hex, toHex } from 'viem';
import { UltraHonkBackend } from '@aztec/bb.js';
import { poseidon } from '@iden3/js-crypto';


/// Extract x and y coordinates from a serialized ECDSA public key.
function extractCoordinates(serializedPubKey: string): { x: number[], y: number[] } {
    // Ensure the key starts with '0x04' which is typical for an uncompressed key.
    if (!serializedPubKey.startsWith('0x04')) {
        throw new Error('The public key does not appear to be in uncompressed format.');
    }

    // The next 64 characters after the '0x04' are the x-coordinate.
    let xHex = serializedPubKey.slice(4, 68);

    // The following 64 characters are the y-coordinate.
    let yHex = serializedPubKey.slice(68, 132);

    // Convert the hex string to a byte array.
    let xBytes = Array.from(Buffer.from(xHex, 'hex'));
    let yBytes = Array.from(Buffer.from(yHex, 'hex'));
    return { x: xBytes, y: yBytes };
}

function extractRSFromSignature(signatureHex: string): number[] {
    if (signatureHex.length !== 132 || !signatureHex.startsWith('0x')) {
        throw new Error('Signature should be a 132-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex'));
}

function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}



async function main(){

    const ownerPrivateKey1 = generatePrivateKey()
    const owner1 = privateKeyToAccount(ownerPrivateKey1)
    const ownerPrivateKey2 = generatePrivateKey()
    const owner2 = privateKeyToAccount(ownerPrivateKey2)
    const ownerPrivateKey3 = generatePrivateKey()
    const owner3 = privateKeyToAccount(ownerPrivateKey3)
   
    const zkSafeModulePrivateOwners = [owner1, owner2, owner3]
    //@ts-ignore
    const modulePrivateOwnersTree = new IMT(poseidon.hash, 3, 0, 2)
    for (var privateOwner of zkSafeModulePrivateOwners) {
        modulePrivateOwnersTree.insert(poseidon.hash([BigInt(privateOwner.address)]))
    }

    
    let txHash = "0x127e5d96be61ee1dedb62628c0659e1af3668ae6d255566be3edc5ffd8606574"
    let op = BigInt("0x127e5d96be61ee1dedb62628c0659e1af3668ae6d255566be3edc5ffd8606574")
    op %= BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")


    const signatures = []
    /*for (let i=0; i<2; i++) {
        signatures.push(await zkSafeModulePrivateOwners[i].signMessage({
            message: txHash as Hex ,
        }))
    }*/
    for (let i=0; i<2; i++) {
        signatures.push(await zkSafeModulePrivateOwners[i].sign({
            hash: txHash as Hex ,
        }))
    }

    //const messageHash = hashMessage(txHash)
    //signatures.sort((sig1, sig2) => ethers.recoverAddress(messageHash, sig1).localeCompare(ethers.recoverAddress(messageHash, sig2)));
    signatures.sort((sig1, sig2) => ethers.recoverAddress(txHash, sig1).localeCompare(ethers.recoverAddress(txHash, sig2)));

    const nil_pubkey = {
        x: Array.from(ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        y: Array.from(ethers.getBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    };
    // Our Nil signature is a signature with r and s set to the G point
    const nil_signature = Array.from(
        ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    
    const ownersIndicesProof: number[] = []
    const ownersPathsProof: any[][] = []

    for (var signature of signatures) {
        //const recoveredAddress = ethers.recoverAddress(messageHash,signature)
        const recoveredAddress = ethers.recoverAddress(txHash,signature)
        const index= await modulePrivateOwnersTree.indexOf(poseidon.hash([BigInt(recoveredAddress)]));
        const addressProof= await modulePrivateOwnersTree.createProof(index);
        addressProof.siblings = addressProof.siblings.map((s) => s[0])
        await ownersIndicesProof.push(Number("0b" + await addressProof.pathIndices.join("")))
        await ownersPathsProof.push(addressProof.siblings)
    }

    const circuitInputs = {
        threshold: 2,
        //signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(messageHash, sig))), 3, nil_pubkey),
        signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig))), 10, nil_pubkey),
        signatures: padArray(signatures.map(extractRSFromSignature), 10, nil_signature),
        //txn_hash: Array.from(ethers.getBytes(messageHash)),
        txn_hash: Array.from(ethers.getBytes(txHash)),
        owners_root:  toHex(modulePrivateOwnersTree.root),
        indices: padArray(ownersIndicesProof.map(indice => toBeHex(indice)), 10, "0x0"),
        siblings: padArray(ownersPathsProof.map(paths => paths.map(path => toBeHex(path))), 10, ["0x0", "0x0", "0x0"])
    };

    //@ts-ignore
    const noir = new Noir(circuit);

    //@ts-ignore
    const { witness } = await noir.execute(circuitInputs);

    const backend = new UltraHonkBackend(circuit.bytecode);

    console.log("Proof Generation ...");
    const proof = await backend.generateProof(witness);
    console.log("Proof: ", proof);

}

async function mainWith10SignatureAnd16Signers(){

    const ownerPrivateKey1 = generatePrivateKey()
    const owner1 = privateKeyToAccount(ownerPrivateKey1)
    const ownerPrivateKey2 = generatePrivateKey()
    const owner2 = privateKeyToAccount(ownerPrivateKey2)
    const ownerPrivateKey3 = generatePrivateKey()
    const owner3 = privateKeyToAccount(ownerPrivateKey3)
  
    const zkSafeModulePrivateOwners = [owner1, owner2, owner3]
    //@ts-ignore
    const modulePrivateOwnersTree = new IMT(poseidon.hash, 4, 0, 2)
    for (var privateOwner of zkSafeModulePrivateOwners) {
        modulePrivateOwnersTree.insert(poseidon.hash([BigInt(privateOwner.address)]))
    }

    
    let txHash = "0x127e5d96be61ee1dedb62628c0659e1af3668ae6d255566be3edc5ffd8606574"
    let op = BigInt("0x127e5d96be61ee1dedb62628c0659e1af3668ae6d255566be3edc5ffd8606574")
    op %= BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")


    const signatures = []
    /*for (let i=0; i<2; i++) {
        signatures.push(await zkSafeModulePrivateOwners[i].signMessage({
            message: txHash as Hex ,
        }))
    }*/
    for (let i=0; i<2; i++) {
        signatures.push(await zkSafeModulePrivateOwners[i].sign({
            hash: txHash as Hex ,
        }))
    }

    //const messageHash = hashMessage(txHash)
    //signatures.sort((sig1, sig2) => ethers.recoverAddress(messageHash, sig1).localeCompare(ethers.recoverAddress(messageHash, sig2)));
    signatures.sort((sig1, sig2) => ethers.recoverAddress(txHash, sig1).localeCompare(ethers.recoverAddress(txHash, sig2)));

    const nil_pubkey = {
        x: Array.from(ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        y: Array.from(ethers.getBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    };
    // Our Nil signature is a signature with r and s set to the G point
    const nil_signature = Array.from(
        ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    
    const ownersIndicesProof: number[] = []
    const ownersPathsProof: any[][] = []

    for (var signature of signatures) {
        //const recoveredAddress = ethers.recoverAddress(messageHash,signature)
        const recoveredAddress = ethers.recoverAddress(txHash,signature)
        const index= await modulePrivateOwnersTree.indexOf(poseidon.hash([BigInt(recoveredAddress)]));
        const addressProof= await modulePrivateOwnersTree.createProof(index);
        addressProof.siblings = addressProof.siblings.map((s) => s[0])
        await ownersIndicesProof.push(Number("0b" + await addressProof.pathIndices.join("")))
        await ownersPathsProof.push(addressProof.siblings)
    }

    const circuitInputs = {
        threshold: 2,
        //signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(messageHash, sig))), 3, nil_pubkey),
        signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig))), 10, nil_pubkey),
        signatures: padArray(signatures.map(extractRSFromSignature), 10, nil_signature),
        //txn_hash: Array.from(ethers.getBytes(messageHash)),
        txn_hash: Array.from(ethers.getBytes(txHash)),
        owners_root:  toHex(modulePrivateOwnersTree.root),
        indices: padArray(ownersIndicesProof.map(indice => toBeHex(indice)), 10, "0x0"),
        siblings: padArray(ownersPathsProof.map(paths => paths.map(path => toBeHex(path))), 10, ["0x0", "0x0", "0x0", "0x0"])
    };

    //@ts-ignore
    const noir = new Noir(circuit);

    //@ts-ignore
    const { witness } = await noir.execute(circuitInputs);

    const backend = new UltraHonkBackend(circuit.bytecode);

    console.log("Proof Generation ...");
    const proof = await backend.generateProof(witness);
    console.log("Proof: ", proof);

}

async function mainWith10Signature(){

    const zkSafeModulePrivateOwners = [];
    for(let i = 0; i<12 ; i++){
        const ownerPrivateKey = generatePrivateKey()
        const owner = privateKeyToAccount(ownerPrivateKey)
        zkSafeModulePrivateOwners.push(owner)
    }
    
    //@ts-ignore
    const modulePrivateOwnersTree = new IMT(poseidon.hash, 4, 0, 2)
    for (var privateOwner of zkSafeModulePrivateOwners) {
        modulePrivateOwnersTree.insert(poseidon.hash([BigInt(privateOwner.address)]))
    }

    
    let txHash = "0x127e5d96be61ee1dedb62628c0659e1af3668ae6d255566be3edc5ffd8606574"
    let op = BigInt("0x127e5d96be61ee1dedb62628c0659e1af3668ae6d255566be3edc5ffd8606574")
    op %= BigInt("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")


    const signatures = []
    /*for (let i=0; i<2; i++) {
        signatures.push(await zkSafeModulePrivateOwners[i].signMessage({
            message: txHash as Hex ,
        }))
    }*/
    for (let i=0; i<10 ; i++) {
        signatures.push(await zkSafeModulePrivateOwners[i].sign({
            hash: txHash as Hex ,
        }))
    }

    //const messageHash = hashMessage(txHash)
    //signatures.sort((sig1, sig2) => ethers.recoverAddress(messageHash, sig1).localeCompare(ethers.recoverAddress(messageHash, sig2)));
    signatures.sort((sig1, sig2) => ethers.recoverAddress(txHash, sig1).localeCompare(ethers.recoverAddress(txHash, sig2)));

    const nil_pubkey = {
        x: Array.from(ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
        y: Array.from(ethers.getBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
    };
    // Our Nil signature is a signature with r and s set to the G point
    const nil_signature = Array.from(
        ethers.getBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
    
    const ownersIndicesProof: number[] = []
    const ownersPathsProof: any[][] = []

    for (var signature of signatures) {
        //const recoveredAddress = ethers.recoverAddress(messageHash,signature)
        const recoveredAddress = ethers.recoverAddress(txHash,signature)
        const index= await modulePrivateOwnersTree.indexOf(poseidon.hash([BigInt(recoveredAddress)]));
        const addressProof= await modulePrivateOwnersTree.createProof(index);
        addressProof.siblings = addressProof.siblings.map((s) => s[0])
        await ownersIndicesProof.push(Number("0b" + await addressProof.pathIndices.join("")))
        await ownersPathsProof.push(addressProof.siblings)
    }

    const circuitInputs = {
        threshold: 10,
        //signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(messageHash, sig))), 3, nil_pubkey),
        signers: padArray(signatures.map((sig) => extractCoordinates(ethers.SigningKey.recoverPublicKey(txHash, sig))), 10, nil_pubkey),
        signatures: padArray(signatures.map(extractRSFromSignature), 10, nil_signature),
        //txn_hash: Array.from(ethers.getBytes(messageHash)),
        txn_hash: Array.from(ethers.getBytes(txHash)),
        owners_root:  toHex(modulePrivateOwnersTree.root),
        indices: padArray(ownersIndicesProof.map(indice => toBeHex(indice)), 10, "0x0"),
        siblings: padArray(ownersPathsProof.map(paths => paths.map(path => toBeHex(path))), 10, ["0x0", "0x0", "0x0", "0x0"])
    };

    //@ts-ignore
    const noir = new Noir(circuit);

    //@ts-ignore
    const { witness } = await noir.execute(circuitInputs);

    const backend = new UltraHonkBackend(circuit.bytecode);

    console.log("Proof Generation ...");
    const proof = await backend.generateProof(witness);
    console.log("Proof: ", proof);

}


mainWith10Signature().then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
});
  //npx ts-node src/signers/MultiSig/ECDSA/Noir/index.ts
  //WebAuthn/Passkeys
  //EdDSA: ZK friendly


