// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: signatures split into array elements through a tuple assignment, a zero recovered address treated
// as failure, and a constant result whose name does not say "magic".
library SigUtil {
    function extractSignature(bytes memory sig, uint256 offset) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, add(offset, 0x20)))
            s := mload(add(sig, add(offset, 0x40)))
            v := byte(0, mload(add(sig, add(offset, 0x60))))
        }
    }
}

contract TupleSplitCosignerWallet {
    using SigUtil for bytes;

    bytes4 internal constant ERC1271_VALIDSIGNATURE = 0x1626ba7e;
    mapping(address => address) public cosignerOf;

    function isValidSignature(bytes32 hash, bytes calldata _signature) external view returns (bytes4) {
        bytes32 operationHash = keccak256(abi.encodePacked(bytes1(0x19), bytes1(0), address(this), hash));
        bytes32[2] memory r;
        bytes32[2] memory s;
        uint8[2] memory v;
        if (_signature.length != 130) {
            return 0;
        }
        (r[0], s[0], v[0]) = _signature.extractSignature(0);
        (r[1], s[1], v[1]) = _signature.extractSignature(65);
        address signer = ecrecover(operationHash, v[0], r[0], s[0]);
        address cosigner = ecrecover(operationHash, v[1], r[1], s[1]);
        if (signer == address(0)) {
            return 0;
        }
        if (cosignerOf[signer] != cosigner) {
            return 0;
        }
        return ERC1271_VALIDSIGNATURE;
    }
}
