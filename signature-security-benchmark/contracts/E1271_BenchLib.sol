// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

interface E1271_IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

interface E1271_IReadOnlyVerifier {
    function verify(address signer, bytes32 hash, bytes calldata signature) external view returns (bool);
}

interface E1271_IMutator {
    function touch(bytes32 hash) external returns (bool);
}

library E1271_BenchECDSA {
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }
}

library E1271_BenchChecker {
    bytes4 internal constant MAGIC = 0x1626ba7e;

    function isValidNow(address signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
        if (signer.code.length == 0) {
            return E1271_BenchECDSA.recover(hash, signature) == signer;
        }
        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature)
        );
        return success && result.length >= 32 && abi.decode(result, (bytes4)) == MAGIC;
    }
}
