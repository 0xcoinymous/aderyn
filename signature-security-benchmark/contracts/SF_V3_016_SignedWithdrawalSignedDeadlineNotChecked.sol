// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SignedWithdrawalSignedDeadlineNotChecked016 {
    mapping(address => uint256) public credit;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function execute(address account, address recipient, uint256 amount, uint256 deadline, bytes calldata signature) external payable {
        address signer_ = account;
        require(credit[account] >= amount, "credit");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(account, recipient, amount, nonce, address(this), block.chainid, deadline));
        require(verifier.verify(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        credit[account] -= amount;
        credit[recipient] += amount;
        executionCount += 1;
    }

    function executionParity() external view returns (uint256) { return executionCount & 1; }

}
