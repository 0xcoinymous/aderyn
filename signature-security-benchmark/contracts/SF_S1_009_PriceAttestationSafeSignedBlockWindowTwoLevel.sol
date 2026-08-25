// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_PriceAttestationSafeSignedBlockWindowTwoLevel009 {
    mapping(address => uint256) public priceOf;
    mapping(bytes32 => bool) public archivedAttestation;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address attestor, address asset, uint256 price, uint32 confidence, uint256 validFromBlock, uint256 validThroughBlock, bytes calldata signature) external payable {
        address signer_ = attestor;
        require(confidence > 0, "confidence");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(attestor, asset, price, confidence, nonce, validFromBlock, validThroughBlock));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.number >= validFromBlock, "early block");
        require(block.number <= validThroughBlock, "late block");
        nonces[signer_] = nonce + 1;
        priceOf[asset] = price;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
