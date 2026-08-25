// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_PriceAttestationSafeIndefiniteRevocableVersion009 {
    mapping(address => uint256) public priceOf;
    mapping(bytes32 => bool) public archivedAttestation;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;


    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address attestor, address asset, uint256 price, uint32 confidence, bytes calldata signature) external payable {
        address signer_ = attestor;
        require(confidence > 0, "confidence");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(attestor, asset, price, confidence, nonce, authVersion));
        require(_signatureOk(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        archivedAttestation[keccak256(abi.encode(asset, price, confidence))] = true;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
