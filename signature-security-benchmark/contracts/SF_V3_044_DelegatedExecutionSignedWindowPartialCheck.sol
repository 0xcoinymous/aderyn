// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_DelegatedExecutionSignedWindowPartialCheck044 {
    mapping(address => uint256) public delegatedCalls;
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

    function execute(address principal, address target, uint256 value, bytes calldata data, uint256 validAfter, uint256 validBefore, bytes calldata signature) external payable {
        address signer_ = principal;
        require(target != address(0), "target");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(principal, target, value, keccak256(data), nonce, address(this), block.chainid, validAfter, validBefore));
        require(_verifyFresh(signer_, digest, signature, validAfter, validBefore), "fresh/signature");
        nonces[signer_] = nonce + 1;
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call");
        delegatedCalls[principal] += 1;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
