// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_PriceAttestationSignedDeadlineNotChecked025 {
    mapping(address => uint256) public priceOf;
    mapping(bytes32 => bool) public archivedAttestation;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function execute(address attestor, address asset, uint256 price, uint32 confidence, uint256 deadline, bytes calldata signature) external payable {
        address signer_ = attestor;
        require(confidence > 0, "confidence");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(attestor, asset, price, confidence, nonce, address(this), block.chainid, deadline));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");

        nonces[signer_] = nonce + 1;
        priceOf[asset] = price;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
