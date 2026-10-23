// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: the domain omits the optional name/version fields but still binds chainId and verifyingContract.
contract OptionalDomainSafe {
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    bytes32 private constant TRANSFER_TYPEHASH =
        keccak256("Transfer(address signer,address recipient,uint256 amount,uint256 nonce)");

    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, block.chainid, address(this)));
    }

    function transferBySig(address signer, address recipient, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        uint256 nonce = nonces[signer];
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, signer, recipient, amount, nonce));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        credits[recipient] += amount;
    }
}
