// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: the wallet recovers the key through a library call and answers with the magic value only for a
// privileged key (Ambire Identity style).
library SignatureValidator {
    function recoverAddr(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "SV_LEN");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "SV_ZERO_SIG");
        return signer;
    }
}

contract LibraryRecoverWallet {
    mapping(address => bytes32) public privileges;

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (privileges[SignatureValidator.recoverAddr(hash, signature)] != bytes32(0)) {
            return 0x1626ba7e;
        } else {
            return 0xffffffff;
        }
    }
}
