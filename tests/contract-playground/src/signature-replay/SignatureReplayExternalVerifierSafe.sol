// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISignatureVerifier {
    function isValid(address signer, bytes32 digest, bytes calldata signature) external view returns (bool);
}

// Verification through an external verifier contract; the nonce in the digest is checked and consumed.
contract SignatureReplayExternalVerifierSafe {
    ISignatureVerifier public verifier;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    constructor(ISignatureVerifier verifier_) { verifier = verifier_; }

    function claim(address account, uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[account], "bad nonce");
        bytes32 digest = keccak256(abi.encode(account, amount, nonce, address(this), block.chainid));
        require(verifier.isValid(account, digest, signature), "bad sig");
        nonces[account] = nonce + 1;
        credits[account] += amount;
    }
}
