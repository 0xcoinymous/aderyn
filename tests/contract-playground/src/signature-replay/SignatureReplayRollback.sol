// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignatureReplayRollback {
    address public signer;
    mapping(address => uint256) public nonces;
    address public target;

    constructor(address signer_, address target_) { signer = signer_; target = target_; }

    function execute(address account, uint256 nonce, bytes calldata data, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[account], "bad nonce");
        bytes32 digest = keccak256(abi.encode(account, nonce, data));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        nonces[account] = nonce + 1;
        (bool success,) = target.call(data);
        require(success, "call failed");
    }
}
