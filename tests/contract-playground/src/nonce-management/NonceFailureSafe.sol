// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: a failed follow-up call is recorded, but the nonce stays consumed.
contract NonceFailureSafe {
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;
    mapping(bytes32 => bool) public failed;

    function execute(address signer, address target, bytes calldata payload, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, target, payload, amount, nonce));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        (bool ok,) = target.call(payload);
        failed[digest] = !ok;
        credits[signer] += amount;
    }
}
