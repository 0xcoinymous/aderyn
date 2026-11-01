// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: the signed nonce is kept by another contract and advanced through it.
interface INonceHolder {
    function getNonce(address token, uint256 tokenId) external view returns (uint256);
    function setNonce(address token, uint256 tokenId, uint256 nonce) external;
}

contract ExternalNonceRegistry {
    INonceHolder public immutable nonceHolder;
    mapping(uint256 => address) public ownerOf;

    constructor(INonceHolder holder) { nonceHolder = holder; }

    function buy(uint256 tokenId, uint256 price, uint8 v, bytes32 r, bytes32 s) external payable {
        address owner = ownerOf[tokenId];
        uint256 nonce = nonceHolder.getNonce(address(this), tokenId);
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, tokenId, price, nonce));
        require(ecrecover(digest, v, r, s) == owner && owner != address(0), "owner should sign");
        require(msg.value == price, "price");
        ownerOf[tokenId] = msg.sender;
        nonceHolder.setNonce(address(this), tokenId, nonce + 1);
    }
}
