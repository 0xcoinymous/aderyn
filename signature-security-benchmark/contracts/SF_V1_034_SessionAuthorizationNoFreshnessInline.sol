// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SessionAuthorizationNoFreshnessInline034 {
    mapping(address => mapping(address => uint256)) public sessionLimit;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function execute(address account, address sessionKey, uint256 limit, bytes calldata signature) external payable {
        address signer_ = account;
        require(sessionKey != address(0), "key");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(account, sessionKey, limit, nonce, address(this), block.chainid));
        require(verifier.verify(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        sessionLimit[account][sessionKey] = limit;
        executionCount += 1;
    }

    function executionParity() external view returns (uint256) { return executionCount & 1; }

}
