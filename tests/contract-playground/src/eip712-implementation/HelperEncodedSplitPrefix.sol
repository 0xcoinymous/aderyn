// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe-style typed data: a helper returns the encoded bytes with the prefix written as two bytes
// (bytes1(0x19), bytes1(0x01)) and the digest is keccak256 of those bytes. Correct EIP-712.
contract HelperEncodedSplitPrefix {
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 private constant SAFE_TX_TYPEHASH =
        keccak256("SafeTx(address to,uint256 value,bytes data,uint256 nonce)");

    address public owner;
    uint256 public nonce;

    constructor(address owner_) { owner = owner_; }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, address(this)));
    }

    function encodeTransactionData(address to, uint256 value, bytes calldata data, uint256 _nonce)
        public
        view
        returns (bytes memory)
    {
        bytes32 safeTxHash = keccak256(abi.encode(SAFE_TX_TYPEHASH, to, value, keccak256(data), _nonce));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeTxHash);
    }

    function execTransaction(address to, uint256 value, bytes calldata data, uint8 v, bytes32 r, bytes32 s)
        external
    {
        bytes memory txHashData = encodeTransactionData(to, value, data, nonce);
        nonce++;
        bytes32 txHash = keccak256(txHashData);
        require(ecrecover(txHash, v, r, s) == owner, "sig");
        (bool ok, ) = to.call{value: value}(data);
        require(ok, "call");
    }
}
