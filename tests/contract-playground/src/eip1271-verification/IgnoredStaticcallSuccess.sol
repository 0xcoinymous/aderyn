// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable consumer: the staticcall success flag is discarded; a reverting signer can leave stale returndata.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

contract IgnoredStaticcallSuccess {
    address public immutable wallet;
    uint256 public accepted;

    constructor(address wallet_) { wallet = wallet_; }

    function _isValid(bytes32 hash, bytes calldata signature) internal view returns (bool) {
        (, bytes memory ret) = wallet.staticcall(abi.encodeWithSelector(IERC1271.isValidSignature.selector, hash, signature));
        return ret.length >= 4 && bytes4(ret) == 0x1626ba7e;
    }

    function execute(bytes32 hash, bytes calldata signature) external {
        require(_isValid(hash, signature), "invalid");
        accepted += 1;
    }
}
