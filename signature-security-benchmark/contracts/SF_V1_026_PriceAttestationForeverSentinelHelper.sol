// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_PriceAttestationForeverSentinelHelper026 {
    mapping(address => uint256) public priceOf;
    mapping(bytes32 => bool) public archivedAttestation;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature
    ) internal view returns (bool) {
        if (SF_FreshnessBenchLib.recover(digest, signature) != signer_) return false;

        return true;
    }

    function execute(address attestor, address asset, uint256 price, uint32 confidence, bytes calldata signature) external payable {
        address signer_ = attestor;
        require(confidence > 0, "confidence");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(attestor, asset, price, confidence, nonce, address(this), block.chainid, type(uint256).max));
        require(_verifyFresh(signer_, digest, signature), "fresh/signature");
        nonces[signer_] = nonce + 1;
        priceOf[asset] = price;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
