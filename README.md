# zkTxAuth

zkTxAuth introduces a new class of authentication and authorization scheme to extend the validation of user operations on the blockchain using programmable cryptography.

ZK changes everything, execution will almost be entirely removed from blockchains via client-side proving. With ZK, we build off-chain trust-minimized computer programs for transaction validation secured by cryptography.

As the Blockchain trusts specific-purpose cryptography, such as public key cryptography algorithms(ECDSA signatures in wallets), it trusts the general-purpose cryptography/programmable cryptography, such as ZK and FHE.

Advanced and complex policies are pseudo-private. Tx validation via signatures(different types of signers) → Tx validation via signatures and proofs

Blockchain transaction validation scheme: 
* 1st generation: private key ownership
* 2nd generation: something programmable using smart contracts
* 3rd generation: something programmable using smart contracts and ZK

The zkTxAuth design enables integration into modern blockchains that support account abstraction(AA). 
