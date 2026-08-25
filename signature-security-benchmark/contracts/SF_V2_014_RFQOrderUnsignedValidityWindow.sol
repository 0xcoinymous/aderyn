// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_RFQOrderUnsignedValidityWindow014 {
    mapping(bytes32 => uint256) public settledAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature, uint256 validAfter, uint256 validBefore
    ) internal view returns (bool) {
        if (SF_FreshnessBenchLib.recover(digest, signature) != signer_) return false;
        if (!(block.timestamp >= validAfter)) return false;
        if (!(block.timestamp <= validBefore)) return false;
        return true;
    }

    function execute(address maker, address taker, uint128 baseAmount, uint128 quoteAmount, bytes32 quoteId, uint256 validAfter, uint256 validBefore, bytes calldata signature) external payable {
        address signer_ = maker;
        require(settledAmount[quoteId] == 0, "settled");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(maker, taker, baseAmount, quoteAmount, quoteId, nonce, address(this), block.chainid));
        require(_verifyFresh(signer_, digest, signature, validAfter, validBefore), "fresh/signature");
        nonces[signer_] = nonce + 1;
        settledAmount[quoteId] = uint256(baseAmount) + uint256(quoteAmount);
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
