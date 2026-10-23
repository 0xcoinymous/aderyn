// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable implementation: the helper verifies a fixed digest and drops the supplied hash, so one signature validates every hash.
contract HelperDropsHash {
    address public immutable owner;
    bytes32 private constant APPROVAL_DIGEST = keccak256("WALLET_APPROVAL");

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

    function _check(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        hash;
        address recovered = _recover(APPROVAL_DIGEST, signature);
        return recovered != address(0) && recovered == owner;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _check(hash, signature) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
