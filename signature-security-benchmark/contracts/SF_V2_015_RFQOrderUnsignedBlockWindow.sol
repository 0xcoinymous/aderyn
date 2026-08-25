// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_RFQOrderUnsignedBlockWindow015 {
    mapping(bytes32 => uint256) public settledAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address maker, address taker, uint128 baseAmount, uint128 quoteAmount, bytes32 quoteId, uint256 validThroughBlock, bytes calldata signature) external payable {
        address signer_ = maker;
        require(settledAmount[quoteId] == 0, "settled");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(maker, taker, baseAmount, quoteAmount, quoteId, nonce));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.number <= validThroughBlock, "late block");
        nonces[signer_] = nonce + 1;
        settledAmount[quoteId] = uint256(baseAmount) + uint256(quoteAmount);
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
