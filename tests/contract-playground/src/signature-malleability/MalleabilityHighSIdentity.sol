// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The signature components are hashed into the one-time key and s is not restricted: (r, n - s, v')
// is a new key for the same authorization.
contract MalleabilityHighSIdentity {
    address public signer;
    mapping(bytes32 => bool) public usedSig;

    constructor(address signer_) { signer = signer_; }

    function withdraw(address payable to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 sigId = keccak256(abi.encodePacked(r, s, v));
        require(!usedSig[sigId], "used");
        bytes32 digest = keccak256(abi.encode(to, amount, address(this), block.chainid));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        usedSig[sigId] = true;
        to.transfer(amount);
    }
}
