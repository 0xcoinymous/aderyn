// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_RFQOrderNoFreshnessInline013 {
    mapping(bytes32 => uint256) public settledAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function execute(address maker, address taker, uint128 baseAmount, uint128 quoteAmount, bytes32 quoteId, bytes calldata signature) external payable {
        address signer_ = maker;
        require(settledAmount[quoteId] == 0, "settled");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(maker, taker, baseAmount, quoteAmount, quoteId, nonce, address(this), block.chainid));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");

        nonces[signer_] = nonce + 1;
        settledAmount[quoteId] = uint256(baseAmount) + uint256(quoteAmount);
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
