// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: when the follow-up call fails, the consumed nonce is restored,
// so the same signature can be submitted again.
contract NonceRollback {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    function execute(address signer, address target, bytes calldata payload, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, target, payload, amount, nonce));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        (bool ok,) = target.call(payload);
        if (!ok) {
            nonces[signer] = nonce;
            return;
        }
        credits[signer] += amount;
    }
}
