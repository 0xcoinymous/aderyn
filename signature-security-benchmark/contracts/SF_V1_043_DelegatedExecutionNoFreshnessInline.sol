// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_DelegatedExecutionNoFreshnessInline043 {
    mapping(address => uint256) public delegatedCalls;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function execute(address principal, address target, uint256 value, bytes calldata data, bytes calldata signature) external payable {
        address signer_ = principal;
        require(target != address(0), "target");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(principal, target, value, keccak256(data), nonce, address(this), block.chainid));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");

        nonces[signer_] = nonce + 1;
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call");
        delegatedCalls[principal] += 1;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
