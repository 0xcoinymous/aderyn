// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: an OpenZeppelin-style SignatureChecker against the owner; the result constant holds the
// isValidSignature selector (Visor style).
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

library SignatureChecker {
    function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
        if (signer.code.length > 0) {
            (bool success, bytes memory result) =
                signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
            return success && result.length == 32 && abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector);
        }
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return ecrecover(hash, v, r, s) == signer;
    }
}

contract SelectorConstantWallet is IERC1271 {
    bytes4 internal constant VALID_SIG = IERC1271.isValidSignature.selector;
    bytes4 internal constant INVALID_SIG = bytes4(0);
    address public owner;

    function isValidSignature(bytes32 permissionHash, bytes memory signature) public view override returns (bytes4) {
        return SignatureChecker.isValidSignatureNow(owner, permissionHash, signature) ? VALID_SIG : INVALID_SIG;
    }
}
