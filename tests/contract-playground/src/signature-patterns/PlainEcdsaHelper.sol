// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Not ERC-1271: an ECDSA helper that happens to be named isValidSignature and returns bool.
contract PlainEcdsaHelper {
    mapping(address => bool) public signers;
    mapping(bytes32 => bool) public withdrawn;
    mapping(address => uint256) public balances;

    function isValidSignature(address signer, bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (bool) {
        return signer == ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)), v, r, s);
    }

    function withdraw(uint256 amount, uint256 nonce, address signer, uint8 v, bytes32 r, bytes32 s) external {
        require(signers[signer], "signer");
        bytes32 hash = keccak256(abi.encode(address(this), block.chainid, msg.sender, amount, nonce));
        require(isValidSignature(signer, hash, v, r, s), "bad sig");
        require(!withdrawn[hash], "used");
        withdrawn[hash] = true;
        balances[msg.sender] -= amount;
    }
}
