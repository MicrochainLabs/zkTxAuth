pragma circom 2.0.0;

include "../../../../node_modules/circomlib/circuits/poseidon.circom";
include "../../../../node_modules/circomlib/circuits/mux1.circom";
include "../../../../node_modules/circomlib/circuits/comparators.circom";

template OperationHasher() {

    signal input accountIdentifier;
    signal input secret;
    signal input op;

    signal output opHash;


    component accountInformationHasher = Poseidon(2);
    accountInformationHasher.inputs[0] <== accountIdentifier;
    accountInformationHasher.inputs[1] <== secret;

    component opHasher = Poseidon(2);
    opHasher.inputs[0] <== accountInformationHasher.out;
    opHasher.inputs[1] <== op;

    opHash <== opHasher.out;

}