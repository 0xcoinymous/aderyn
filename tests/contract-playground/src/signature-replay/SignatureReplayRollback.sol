// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The nonce is consumed before the external call; if the call fails the whole transaction reverts,
// including its effect, so the signature is still used at most once. Not reported.
contract SignatureReplayRollback {
    address public signer;
    mapping(address => uint256) public nonces;
    address public target;

    constructor(address signer_, address target_) { signer = signer_; target = target_; }

    function execute(address account, uint256 nonce, bytes calldata data, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[account], "bad nonce");
        bytes32 digest = keccak256(abi.encode(account, nonce, data, address(this), block.chainid));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        nonces[account] = nonce + 1;
        (bool success,) = target.call(data);
        require(success, "call failed");
    }
}
