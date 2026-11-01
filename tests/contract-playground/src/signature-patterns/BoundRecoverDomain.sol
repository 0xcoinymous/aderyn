// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: `using ECDSA for bytes32`; the digest is the receiver of `hash.recover(signature)` and binds
// the contract, the chain and a consumed nonce.
library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(hash, v, r, s);
    }
}

contract BoundRecoverDomain {
    using ECDSA for bytes32;
    address public immutable signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;

    constructor(address signer_) { signer = signer_; }

    function claim(uint256 amount, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encode(msg.sender, amount, nonces[msg.sender]++, address(this), block.chainid));
        require(hash.recover(signature) == signer, "bad sig");
        balances[msg.sender] += amount;
    }
}
