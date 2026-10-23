// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable consumer: any signer without code (EOA or not-yet-deployed address) is accepted without checking a signature.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

contract UnsafeEOAFallback {
    uint256 public accepted;
    mapping(address => bool) public approved;

    function _isValid(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signer.code.length == 0) return true;
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function approve(address signer, bytes32 hash, bytes calldata signature) external {
        require(_isValid(signer, hash, signature), "invalid");
        approved[signer] = true;
        accepted += 1;
    }
}
