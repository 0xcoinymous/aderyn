// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable implementation: the hash is taken as bytes, so the selector is not 0x1626ba7e and callers never reach it.
contract WrongShape {
    address public immutable owner;

    constructor(address owner_) { owner = owner_; }

    function _recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
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

    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4) {
        address recovered = _recover(keccak256(data), signature);
        return recovered != address(0) && recovered == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
