// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// v is normalised permissively and the raw signature bytes are the one-time key: v = 0/1 and v = 27/28
// are two keys for the same authorization.
contract MalleabilityPermissiveVIdentity {
    address public signer;
    mapping(bytes32 => bool) public usedSig;

    constructor(address signer_) { signer = signer_; }

    function withdraw(address payable to, uint256 amount, bytes calldata signature) external {
        bytes32 key = keccak256(signature);
        require(!usedSig[key], "used");
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(signature, (bytes32, bytes32, uint8));
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "s");
        if (v < 27) v += 27;
        bytes32 digest = keccak256(abi.encode(to, amount, address(this), block.chainid));
        require(ecrecover(digest, v, r, s) == signer, "bad sig");
        usedSig[key] = true;
        to.transfer(amount);
    }
}
