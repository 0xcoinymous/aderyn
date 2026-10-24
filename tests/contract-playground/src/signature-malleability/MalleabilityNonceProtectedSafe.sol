// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Raw ecrecover without an s check, but replay protection comes from the signed nonce: the malleated
// signature authorizes the same, already consumed nonce.
contract MalleabilityNonceProtectedSafe {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;

    function permit(address owner, address spender, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(
            abi.encode(owner, spender, value, nonces[owner]++, address(this), block.chainid)
        );
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == owner, "bad sig");
        allowance[owner][spender] = value;
    }
}
