// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: unordered nonces in a bitmap (Permit2 style); a used bit is rejected before it is set.
contract BitmapNonceSafe {
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;
    mapping(address => uint256) public credits;

    function claim(address signer, address recipient, uint256 amount, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, nonce));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        uint256 wordPos = nonce >> 8;
        uint256 bit = 1 << (nonce & 0xff);
        uint256 flipped = nonceBitmap[signer][wordPos] ^= bit;
        require(flipped & bit != 0, "nonce used");
        credits[recipient] += amount;
    }
}
