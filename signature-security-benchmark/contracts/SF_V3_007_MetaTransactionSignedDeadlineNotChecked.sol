// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_MetaTransactionSignedDeadlineNotChecked007 {
    mapping(address => uint256) public executed;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function execute(address from, address target, bytes calldata callData, uint256 deadline, bytes calldata signature) external payable {
        address signer_ = from;
        require(target != address(0), "target");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(from, target, keccak256(callData), nonce, address(this), block.chainid, deadline));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");

        nonces[signer_] = nonce + 1;
        (bool ok,) = target.call(callData);
        require(ok, "call");
        executed[from] += 1;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
