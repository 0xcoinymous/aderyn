// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: two signatures split with inline assembly, verified with a bound `digest.recover(sig)` call, and
// the magic value assigned to the named return variable (Dharma smart wallet style).
library ECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
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

contract AssemblySplitWallet {
    using ECDSA for bytes32;

    bytes4 internal constant _ERC_1271_MAGIC_VALUE = 0x1626ba7e;
    address internal _userSigningKey;
    address internal _serviceKey;

    function isValidSignature(bytes32 digest, bytes calldata signatures) external view returns (bytes4 magicValue) {
        if (signatures.length != 130) {
            revert("length");
        }
        bytes memory signaturesInMemory = signatures;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signaturesInMemory, 0x20))
            s := mload(add(signaturesInMemory, 0x40))
            v := byte(0, mload(add(signaturesInMemory, 0x60)))
        }
        bytes memory serviceSignature = abi.encodePacked(r, s, v);
        assembly {
            r := mload(add(signaturesInMemory, 0x61))
            s := mload(add(signaturesInMemory, 0x81))
            v := byte(0, mload(add(signaturesInMemory, 0xa1)))
        }
        bytes memory userSignature = abi.encodePacked(r, s, v);
        if (_userSigningKey != digest.recover(userSignature)) {
            revert("user");
        }
        if (_serviceKey != digest.recover(serviceSignature)) {
            revert("service");
        }
        magicValue = _ERC_1271_MAGIC_VALUE;
    }
}
