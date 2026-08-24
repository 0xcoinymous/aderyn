// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

library SM_MalleabilityBenchLib {
    uint256 internal constant SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 internal constant SECP256K1_HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    uint256 internal constant S_MASK = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    function recoverRaw(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(digest, v, r, s);
    }

    function recoverCanonical(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address signer) {
        require(uint256(s) > 0 && uint256(s) <= SECP256K1_HALF_N, "non-canonical s");
        require(v == 27 || v == 28, "invalid v");
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "invalid signature");
    }

    function tryRecoverCanonical(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address signer, bool ok) {
        if (uint256(s) == 0 || uint256(s) > SECP256K1_HALF_N) return (address(0), false);
        if (v != 27 && v != 28) return (address(0), false);
        signer = ecrecover(digest, v, r, s);
        ok = signer != address(0);
    }

    function recoverParity01(bytes32 digest, uint8 parity, bytes32 r, bytes32 s) internal pure returns (address signer) {
        require(parity <= 1, "invalid parity");
        require(uint256(s) > 0 && uint256(s) <= SECP256K1_HALF_N, "non-canonical s");
        signer = ecrecover(digest, parity + 27, r, s);
        require(signer != address(0), "invalid signature");
    }

    function split65(bytes calldata signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(signature.length == 65, "length");
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
    }

    function splitFlexible(bytes calldata signature) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        if (signature.length == 65) {
            assembly {
                r := calldataload(signature.offset)
                s := calldataload(add(signature.offset, 32))
                v := byte(0, calldataload(add(signature.offset, 64)))
            }
        } else if (signature.length == 64) {
            bytes32 vs;
            assembly {
                r := calldataload(signature.offset)
                vs := calldataload(add(signature.offset, 32))
            }
            s = bytes32(uint256(vs) & S_MASK);
            v = uint8((uint256(vs) >> 255) + 27);
        } else {
            revert("length");
        }
    }

    function recoverFlexibleCanonical(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        (bytes32 r, bytes32 s, uint8 v) = splitFlexible(signature);
        return recoverCanonical(digest, v, r, s);
    }
}
