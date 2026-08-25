// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_RFQOrderSafeMonotonicRoundHelper005 {
    mapping(bytes32 => uint256) public settledAmount;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _verifyOnly(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return verifier.verify(signer_, digest, signature);
    }

    function execute(address maker, address taker, uint128 baseAmount, uint128 quoteAmount, bytes32 quoteId, uint64 round, bytes calldata signature) external payable {
        address signer_ = maker;
        require(settledAmount[quoteId] == 0, "settled");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(maker, taker, baseAmount, quoteAmount, quoteId, nonce, address(this), block.chainid, round));
        require(_verifyOnly(signer_, digest, signature), "signature");
        require(uint256(round) > latestFreshness[signer_], "old round");
        latestFreshness[signer_] = uint256(round);
        nonces[signer_] = nonce + 1;
        settledAmount[quoteId] = uint256(baseAmount) + uint256(quoteAmount);
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
