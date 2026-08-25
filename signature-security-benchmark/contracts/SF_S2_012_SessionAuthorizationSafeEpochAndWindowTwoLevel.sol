// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SessionAuthorizationSafeEpochAndWindowTwoLevel012 {
    mapping(address => mapping(address => uint256)) public sessionLimit;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

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

    function execute(address account, address sessionKey, uint256 limit, uint64 epoch, uint256 deadline, bytes calldata signature) external payable {
        address signer_ = account;
        require(sessionKey != address(0), "key");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(account, sessionKey, limit, nonce, epoch, deadline));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(uint256(epoch) >= latestFreshness[signer_], "old epoch");
        require(block.timestamp <= deadline, "expired");
        latestFreshness[signer_] = uint256(epoch);
        nonces[signer_] = nonce + 1;
        sessionLimit[account][sessionKey] = limit;
        executionCount += 1;
    }

    function executionParity() external view returns (uint256) { return executionCount & 1; }

}
