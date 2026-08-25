// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SignedClaimForeverSentinelHelper020 {
    mapping(bytes32 => bool) public claimed;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature
    ) internal view returns (bool) {
        if (SF_FreshnessBenchLib.recover(digest, signature) != signer_) return false;

        return true;
    }

    function execute(address claimant, bytes32 claimId, uint256 amount, bytes calldata signature) external payable {
        address signer_ = claimant;
        require(!claimed[claimId], "claimed");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(claimant, claimId, amount, nonce, address(this), block.chainid, type(uint256).max));
        require(_verifyFresh(signer_, digest, signature), "fresh/signature");
        nonces[signer_] = nonce + 1;
        claimed[claimId] = true;
        rewards[claimant] += amount;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

}
