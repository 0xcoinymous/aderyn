// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_TemporaryApprovalUnsignedDeadline037 {
    mapping(address => mapping(address => uint256)) public approvedAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function execute(address owner, address delegate, uint256 amount, uint256 deadline, bytes calldata signature) external payable {
        address signer_ = owner;
        require(delegate != address(0), "delegate");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(owner, delegate, amount, nonce, address(this), block.chainid));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");
        require(block.timestamp <= deadline, "expired");
        nonces[signer_] = nonce + 1;
        approvedAmount[owner][delegate] = amount;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

}
