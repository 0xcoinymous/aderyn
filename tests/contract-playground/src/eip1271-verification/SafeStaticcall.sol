// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe consumer: checks success, return length and the exact magic value.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

contract SafeStaticcall {
    address public immutable wallet;
    uint256 public accepted;

    constructor(address wallet_) { wallet = wallet_; }

    function _isValid(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        (bool success, bytes memory ret) = wallet.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function execute(bytes32 hash, bytes calldata signature) external {
        require(_isValid(hash, signature), "invalid");
        accepted += 1;
    }
}
