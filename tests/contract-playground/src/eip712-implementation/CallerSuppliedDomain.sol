// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Vulnerable: the caller chooses the domain separator, so signatures made for another
// contract or chain are accepted here.
contract CallerSuppliedDomain {
    bytes32 private constant TRANSFER_TYPEHASH =
        keccak256("Transfer(address signer,address recipient,uint256 amount,uint256 nonce)");

    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    function transferBySig(bytes32 domainSeparator, address signer, address recipient, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        uint256 nonce = nonces[signer];
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, signer, recipient, amount, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        credits[recipient] += amount;
    }
}
