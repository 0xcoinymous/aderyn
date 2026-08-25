// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_TemporaryApprovalSignedWindowPartialCheck038 {
    mapping(address => mapping(address => uint256)) public approvedAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature, uint256 validAfter, uint256 validBefore
    ) internal view returns (bool) {
        if (SF_FreshnessBenchLib.recover(digest, signature) != signer_) return false;
        if (!(block.timestamp >= validAfter)) return false;
        return true;
    }

    function execute(address owner, address delegate, uint256 amount, uint256 validAfter, uint256 validBefore, bytes calldata signature) external payable {
        address signer_ = owner;
        require(delegate != address(0), "delegate");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(owner, delegate, amount, nonce, address(this), block.chainid, validAfter, validBefore));
        require(_verifyFresh(signer_, digest, signature, validAfter, validBefore), "fresh/signature");
        nonces[signer_] = nonce + 1;
        approvedAmount[owner][delegate] = amount;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

}
