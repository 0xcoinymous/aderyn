// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The signature hash is the one-time key, but s is restricted through a cast alias and v to 27/28.
contract MalleabilityAliasLowSSafe {
    address public signer;
    mapping(bytes32 => bool) public usedSig;

    constructor(address signer_) { signer = signer_; }

    function withdraw(address payable to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        require(v == 27 || v == 28, "v");
        uint256 su = uint256(s);
        require(su != 0 && su <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "s");
        bytes32 sigId = keccak256(abi.encodePacked(r, s, v));
        require(!usedSig[sigId], "used");
        bytes32 digest = keccak256(abi.encode(to, amount, address(this), block.chainid));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        usedSig[sigId] = true;
        to.transfer(amount);
    }
}
