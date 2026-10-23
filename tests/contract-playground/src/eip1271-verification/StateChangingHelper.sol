// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable implementation: validation writes storage through a helper (ERC-1271 validation must be read-only).
contract StateChangingHelper {
    address public immutable owner;
    uint256 public validationCount;

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

    function _validate(bytes32 hash, bytes calldata signature) internal returns (bytes4) {
        validationCount += 1;
        address recovered = _recover(hash, signature);
        return recovered != address(0) && recovered == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external returns (bytes4) {
        return _validate(hash, signature);
    }
}
