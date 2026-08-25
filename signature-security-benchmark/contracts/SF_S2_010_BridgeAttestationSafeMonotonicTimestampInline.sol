// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_BridgeAttestationSafeMonotonicTimestampInline010 {
    mapping(bytes32 => bool) public released;
    mapping(address => uint256) public bridged;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function execute(address validator, bytes32 messageId, address recipient, uint256 amount, uint256 issuedAt, bytes calldata signature) external payable {
        address signer_ = validator;
        require(!released[messageId], "released");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(validator, messageId, recipient, amount, nonce, address(this), block.chainid, issuedAt));
        require(verifier.verify(signer_, digest, signature), "signature");
        require(issuedAt > latestFreshness[signer_], "old");
        require(issuedAt <= block.timestamp, "future");
        require(block.timestamp - issuedAt <= 300, "stale");
        latestFreshness[signer_] = issuedAt;
        nonces[signer_] = nonce + 1;
        released[messageId] = true;
        bridged[recipient] += amount;
        executionCount += 1;
    }

    function nextNonce(address account) external view returns (uint256) { return nonces[account]; }

}
