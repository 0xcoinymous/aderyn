// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_MetaTransactionForeverSentinelHelper008 {
    mapping(address => uint256) public executed;
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

    function execute(address from, address target, bytes calldata callData, bytes calldata signature) external payable {
        address signer_ = from;
        require(target != address(0), "target");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(from, target, keccak256(callData), nonce, address(this), block.chainid, type(uint256).max));
        require(_verifyFresh(signer_, digest, signature), "fresh/signature");
        nonces[signer_] = nonce + 1;
        (bool ok,) = target.call(callData);
        require(ok, "call");
        executed[from] += 1;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
