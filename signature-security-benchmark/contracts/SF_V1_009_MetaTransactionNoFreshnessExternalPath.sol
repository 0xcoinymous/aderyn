// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_MetaTransactionNoFreshnessExternalPath009 {
    mapping(address => uint256) public executed;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return verifier.verify(signer_, digest, signature);
    }

    function execute(address from, address target, bytes calldata callData, bytes calldata signature) external payable {
        address signer_ = from;
        require(target != address(0), "target");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(from, target, keccak256(callData), nonce));
        require(_signatureOk(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        (bool ok,) = target.call(callData);
        require(ok, "call");
        executed[from] += 1;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

}
