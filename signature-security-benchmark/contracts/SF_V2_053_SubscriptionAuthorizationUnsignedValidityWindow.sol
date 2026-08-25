// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SubscriptionAuthorizationUnsignedValidityWindow053 {
    mapping(address => uint256) public paid;
    mapping(bytes32 => bool) public chargedCycle;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature, uint256 validAfter, uint256 validBefore
    ) internal view returns (bool) {
        if (!verifier.verify(signer_, digest, signature)) return false;
        if (!(block.timestamp >= validAfter)) return false;
        if (!(block.timestamp <= validBefore)) return false;
        return true;
    }

    function execute(address subscriber, address merchant, uint96 amount, uint32 cycle, uint256 validAfter, uint256 validBefore, bytes calldata signature) external payable {
        address signer_ = subscriber;
        require(merchant != address(0), "merchant");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(subscriber, merchant, amount, cycle, nonce, address(this), block.chainid));
        require(_verifyFresh(signer_, digest, signature, validAfter, validBefore), "fresh/signature");
        nonces[signer_] = nonce + 1;
        bytes32 key = keccak256(abi.encode(subscriber, merchant, cycle));
        require(!chargedCycle[key], "cycle");
        chargedCycle[key] = true;
        paid[merchant] += amount;
        executionCount += 1;
    }

    function executionParity() external view returns (uint256) { return executionCount & 1; }

}
