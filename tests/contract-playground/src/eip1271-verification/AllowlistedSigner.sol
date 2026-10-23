// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe consumer: only admin-approved contract signers are queried.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

contract AllowlistedSigner {
    address public immutable admin;
    mapping(address => bool) public allowedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) {
        admin = msg.sender;
        allowedSigner[signer_] = true;
    }

    function addSigner(address signer_) external {
        require(msg.sender == admin, "admin");
        allowedSigner[signer_] = true;
    }

    function _isValid(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (!allowedSigner[signer]) return false;
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external {
        require(_isValid(signer, hash, signature), "invalid");
        accepted += 1;
        lastHash = hash;
    }
}
