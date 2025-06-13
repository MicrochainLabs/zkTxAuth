pragma circom 2.0.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";
include "./tree.circom";
include "./operation_hasher.circom";

template ContractValueWhitelistPolicy(transactionNumber, smartContractCallTreeLevel, valueTransferTreeLevel) {

    signal input smartAccount;
    signal input configId;
    signal input contractWhitelistRoot;
    signal input valueWhitelistRoot; 
    signal input userOpHash;

    //Extracted by the smart contract account (validateUserOp) from the user operation calldata 
    signal input dest[transactionNumber];
    signal input value[transactionNumber];
    signal input functionSelector[transactionNumber]; //(ERC20, transfer) Hex: 0xa9059cbb
    signal input erc20TransferTo[transactionNumber];
    //signal input erc20TransferAmount[transactionNumber];
        
    signal input nativeCoinTransferSiblings[transactionNumber][valueTransferTreeLevel];
    signal input nativeCoinTransferIndices[transactionNumber][valueTransferTreeLevel];
    signal input smartContractCallSiblings[transactionNumber][smartContractCallTreeLevel];
    signal input smartContractCallPathIndices[transactionNumber][smartContractCallTreeLevel];
    signal input erc20TransferSiblings[transactionNumber][valueTransferTreeLevel];
    signal input erc20TransferPathIndices[transactionNumber][valueTransferTreeLevel];

    signal output permissionRoot;
    signal output accountPermissionUserOpHash;

    signal toTreeRootPerTransaction[transactionNumber];
    signal computedToTreeRootPerTransaction[transactionNumber];
    signal smartContractCallTreeRootPerTransaction[transactionNumber];
    signal computedSmartContractCallTreeRootPerTransaction[transactionNumber];
    signal erc20ToTreeRootPerTransaction[transactionNumber];
    signal computedErc20ToTreeRootPerTransaction[transactionNumber];
    signal smartAccountPermission;


    //Compute permission tree root
    component permissionTree01 = Poseidon(2);
    permissionTree01.inputs[0] <== smartAccount;
    permissionTree01.inputs[1] <== configId;

    component permissionTree23 = Poseidon(2);
    permissionTree23.inputs[0] <== contractWhitelistRoot;
    permissionTree23.inputs[1] <== valueWhitelistRoot;

    component permissionTree = Poseidon(2);
    permissionTree.inputs[0] <== permissionTree01.out;
    permissionTree.inputs[1] <== permissionTree23.out;
    permissionRoot <== permissionTree.out;


    component isZeroEthAmount[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        isZeroEthAmount[i] = IsZero();
        isZeroEthAmount[i].in <== value[i];
    }
    component ethTransferToAddressInclusionValidity[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        ethTransferToAddressInclusionValidity[i] = MerkleTreeInclusionProof(valueTransferTreeLevel);
        ethTransferToAddressInclusionValidity[i].leaf <== dest[i];
        for (var j=0; j<valueTransferTreeLevel; j++) {
            ethTransferToAddressInclusionValidity[i].siblings[j] <== nativeCoinTransferSiblings[i][j];
            ethTransferToAddressInclusionValidity[i].pathIndices[j] <== nativeCoinTransferIndices[i][j];
        }
    }
    for (var i=0; i<transactionNumber; i++) {
        toTreeRootPerTransaction[i] <== valueWhitelistRoot * (1 - isZeroEthAmount[i].out);
        computedToTreeRootPerTransaction[i] <== ethTransferToAddressInclusionValidity[i].root * (1 - isZeroEthAmount[i].out);
        toTreeRootPerTransaction[i] === computedToTreeRootPerTransaction[i];
    }


    
    component isZeroFunctionSelector[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        isZeroFunctionSelector[i] = IsZero();
        isZeroFunctionSelector[i].in <== functionSelector[i];
    }
    component callSmartContractAddressInclusionValidity[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        callSmartContractAddressInclusionValidity[i] = MerkleTreeInclusionProof(smartContractCallTreeLevel);
        callSmartContractAddressInclusionValidity[i].leaf <== dest[i];
        for (var j=0; j<smartContractCallTreeLevel; j++) {
            callSmartContractAddressInclusionValidity[i].siblings[j] <== smartContractCallSiblings[i][j];
            callSmartContractAddressInclusionValidity[i].pathIndices[j] <== smartContractCallPathIndices[i][j];
        }
    }
    for (var i=0; i<transactionNumber; i++) {
        smartContractCallTreeRootPerTransaction[i] <== contractWhitelistRoot * (1 - isZeroFunctionSelector[i].out);
        computedSmartContractCallTreeRootPerTransaction[i] <== callSmartContractAddressInclusionValidity[i].root * (1 - isZeroFunctionSelector[i].out);
        smartContractCallTreeRootPerTransaction[i] === computedSmartContractCallTreeRootPerTransaction[i];
    }


    //2835717307 transfer(to, amount) function selector
    //component isErc20Transfer[transactionNumber];
    component isTokenTransferOrApprove[transactionNumber];
     for (var i=0; i<transactionNumber; i++) {
        //isErc20Transfer[i] = IsEqual();
        isTokenTransferOrApprove[i] = IsZero();
        isTokenTransferOrApprove[i].in <== erc20TransferTo[i];
    }
    component erc20TransferToAddressInclusionValidity[transactionNumber];
    for (var i=0; i<transactionNumber; i++) {
        erc20TransferToAddressInclusionValidity[i] = MerkleTreeInclusionProof(valueTransferTreeLevel);
        erc20TransferToAddressInclusionValidity[i].leaf <== erc20TransferTo[i];
        for (var j=0; j<valueTransferTreeLevel; j++) {
            erc20TransferToAddressInclusionValidity[i].siblings[j] <== erc20TransferSiblings[i][j];
            erc20TransferToAddressInclusionValidity[i].pathIndices[j] <== erc20TransferPathIndices[i][j];
        }
    }
    for (var i=0; i<transactionNumber; i++) {
        erc20ToTreeRootPerTransaction[i] <== valueWhitelistRoot * (1 - isTokenTransferOrApprove[i].out);
        computedErc20ToTreeRootPerTransaction[i] <== erc20TransferToAddressInclusionValidity[i].root * (1 - isTokenTransferOrApprove[i].out);
        erc20ToTreeRootPerTransaction[i] === computedErc20ToTreeRootPerTransaction[i];
    }


    component operationHasher = OperationHasher();
    smartAccountPermission <== smartAccount + configId;
    operationHasher.accountIdentifier <== smartAccountPermission;
    operationHasher.secret <== permissionRoot;
    operationHasher.op <== userOpHash;

    accountPermissionUserOpHash <== operationHasher.opHash;

}

component main {public [smartAccount, configId, userOpHash, dest, value, functionSelector, erc20TransferTo]} = ContractValueWhitelistPolicy(2, 17, 17);