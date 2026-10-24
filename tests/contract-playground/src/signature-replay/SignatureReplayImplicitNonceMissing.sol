// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The nonce is encoded in the signed digest but never advanced, so the same signature stays valid.
contract SignatureReplayImplicitNonceMissing {
    address public signer;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address signer_) { signer = signer_; }

    function permitInline(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(
            abi.encode(owner, spender, value, nonces[owner], address(this), block.chainid)
        );
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        allowance[owner][spender] = value;
    }

    function permitHelper(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(
            abi.encode(owner, spender, value, _peekNonce(owner), address(this), block.chainid)
        );
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        allowance[owner][spender] = value;
    }

    function _peekNonce(address owner) internal view returns (uint256) {
        return nonces[owner];
    }
}
