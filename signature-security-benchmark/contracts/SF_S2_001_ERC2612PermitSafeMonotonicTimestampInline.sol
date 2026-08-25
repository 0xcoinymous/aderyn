// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_ERC2612PermitSafeMonotonicTimestampInline001 {
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

    uint256 public executionCount;


    function execute(address owner, address spender, uint256 value, uint256 issuedAt, bytes calldata signature) external payable {
        address signer_ = owner;
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(owner, spender, value, nonce, address(this), block.chainid, issuedAt));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");
        require(issuedAt > latestFreshness[signer_], "old");
        require(issuedAt <= block.timestamp, "future");
        require(block.timestamp - issuedAt <= 300, "stale");
        latestFreshness[signer_] = issuedAt;
        nonces[signer_] = nonce + 1;
        allowance[owner][spender] = value;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

}
