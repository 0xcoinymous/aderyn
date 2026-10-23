// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable consumer: any non-zero bytes4 is accepted instead of the exact magic value 0x1626ba7e.
interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

contract NonzeroMagic {
    address public immutable wallet;
    uint256 public accepted;

    constructor(address wallet_) { wallet = wallet_; }

    function execute(bytes32 hash, bytes calldata signature) external {
        bytes4 result = IERC1271(wallet).isValidSignature(hash, signature);
        require(result != bytes4(0), "invalid");
        accepted += 1;
    }
}
