// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

library NM_NonceBenchLib {
    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address signer) {
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "invalid signature");
    }

    function recoverChecked(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address signer) {
        require(v == 27 || v == 28, "invalid v");
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0, "high s");
        signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "invalid signature");
    }
}

interface NM_IExternalVerifier {
    function isValid(address expectedSigner, bytes32 digest, uint8 v, bytes32 r, bytes32 s) external view returns (bool);
}

interface NM_IERC1271Like {
    function isValidSignature(bytes32 digest, bytes calldata signature) external view returns (bytes4);
}

interface NM_IAction {
    function run(bytes calldata payload) external returns (bool);
}

abstract contract NM_NonceSignerBase {
    function _recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        return ecrecover(digest, v, r, s);
    }
}
