// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

library SF_FreshnessBenchLib {
    uint256 internal constant SF_SECP256K1N_HALF = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function recover(bytes32 digest, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(s) > SF_SECP256K1N_HALF) return address(0);
        if (v != 27 && v != 28) return address(0);
        return ecrecover(digest, v, r, s);
    }
}

interface SF_IFreshnessVerifier {
    function verify(address signer, bytes32 digest, bytes calldata signature) external view returns (bool);
}
