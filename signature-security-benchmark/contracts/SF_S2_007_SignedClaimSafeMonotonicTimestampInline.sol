// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SignedClaimSafeMonotonicTimestampInline007 {
    mapping(bytes32 => bool) public claimed;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

    uint256 public executionCount;


    function execute(address claimant, bytes32 claimId, uint256 amount, uint256 issuedAt, bytes calldata signature) external payable {
        address signer_ = claimant;
        require(!claimed[claimId], "claimed");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(claimant, claimId, amount, nonce, address(this), block.chainid, issuedAt));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");
        require(issuedAt > latestFreshness[signer_], "old");
        require(issuedAt <= block.timestamp, "future");
        require(block.timestamp - issuedAt <= 300, "stale");
        latestFreshness[signer_] = issuedAt;
        nonces[signer_] = nonce + 1;
        claimed[claimId] = true;
        rewards[claimant] += amount;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

}
