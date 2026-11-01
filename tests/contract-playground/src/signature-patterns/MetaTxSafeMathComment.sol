// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Safe: the nonce is advanced with SafeMath (`nonces[user].add(1)`), and a comment with parentheses
// precedes the write.
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");
        return c;
    }
}

contract MetaTxSafeMathComment {
    using SafeMath for uint256;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public balances;

    function executeMetaTransaction(address user, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(user, amount, nonces[user], address(this), block.chainid));
        require(ecrecover(digest, v, r, s) == user && user != address(0), "bad sig");
        // increase nonce for user (to avoid re-use)
        nonces[user] = nonces[user].add(1);
        balances[user] += amount;
    }
}
