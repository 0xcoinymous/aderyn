// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignatureReplayCrossFunction {
    address public signer;
    mapping(bytes32 => bool) public usedPrimary;
    mapping(bytes32 => bool) public usedAlternate;
    uint256 public executions;

    constructor(address signer_) { signer = signer_; }

    function primary(bytes32 id, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedPrimary[id], "used");
        bytes32 digest = keccak256(abi.encode(id));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        usedPrimary[id] = true;
        executions++;
    }

    function alternate(bytes32 id, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedAlternate[id], "used");
        bytes32 digest = keccak256(abi.encode(id));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        usedAlternate[id] = true;
        executions++;
    }
}
