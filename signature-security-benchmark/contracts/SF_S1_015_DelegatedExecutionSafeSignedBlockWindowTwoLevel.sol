// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_DelegatedExecutionSafeSignedBlockWindowTwoLevel015 {
    mapping(address => uint256) public delegatedCalls;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address principal, address target, uint256 value, bytes calldata data, uint256 validFromBlock, uint256 validThroughBlock, bytes calldata signature) external payable {
        address signer_ = principal;
        require(target != address(0), "target");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(principal, target, value, keccak256(data), nonce, validFromBlock, validThroughBlock));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.number >= validFromBlock, "early block");
        require(block.number <= validThroughBlock, "late block");
        nonces[signer_] = nonce + 1;
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call");
        delegatedCalls[principal] += 1;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
