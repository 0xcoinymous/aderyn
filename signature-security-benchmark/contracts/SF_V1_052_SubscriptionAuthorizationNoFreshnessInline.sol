// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SubscriptionAuthorizationNoFreshnessInline052 {
    mapping(address => uint256) public paid;
    mapping(bytes32 => bool) public chargedCycle;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function execute(address subscriber, address merchant, uint96 amount, uint32 cycle, bytes calldata signature) external payable {
        address signer_ = subscriber;
        require(merchant != address(0), "merchant");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(subscriber, merchant, amount, cycle, nonce, address(this), block.chainid));
        require(verifier.verify(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        bytes32 key = keccak256(abi.encode(subscriber, merchant, cycle));
        require(!chargedCycle[key], "cycle");
        chargedCycle[key] = true;
        paid[merchant] += amount;
        executionCount += 1;
    }

    function executionParity() external view returns (uint256) { return executionCount & 1; }

}
