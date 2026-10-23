// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable consumer: the caller chooses which contract signer is asked, so an attacker deploys one that always approves.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

contract UserSuppliedSigner {
    uint256 public accepted;
    bytes32 public lastHash;

    function _isValid(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external {
        require(_isValid(signer, hash, signature), "invalid");
        accepted += 1;
        lastHash = hash;
    }
}
