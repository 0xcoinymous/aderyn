// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignatureReplayCheckedNotConsumed {
    address public signer;
    mapping(bytes32 => bool) public used;
    uint256 public executions;

    constructor(address signer_) { signer = signer_; }

    function execute(bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!used[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(authorizationId));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        executions++;
    }
}
