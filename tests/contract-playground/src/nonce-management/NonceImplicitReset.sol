// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The nonce is consumed implicitly in the signed digest, but another function can reset it, which
// makes every earlier signature of that owner valid again.
contract NonceImplicitReset {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    function permit(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(
            abi.encode(owner, spender, value, nonces[owner]++, address(this), block.chainid)
        );
        require(ecrecover(digest, v, r, s) == owner, "bad sig");
        allowance[owner][spender] = value;
    }

    function resetNonce(address owner) external {
        nonces[owner] = 0;
    }
}
