// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_BridgeAttestationUnsignedIssuedAtWindow030 {
    mapping(bytes32 => bool) public released;
    mapping(address => uint256) public bridged;
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

    function execute(address validator, bytes32 messageId, address recipient, uint256 amount, uint256 issuedAt, bytes calldata signature) external payable {
        address signer_ = validator;
        require(!released[messageId], "released");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(validator, messageId, recipient, amount, nonce));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(issuedAt <= block.timestamp, "future");
        require(block.timestamp - issuedAt <= 300, "stale");
        nonces[signer_] = nonce + 1;
        released[messageId] = true;
        bridged[recipient] += amount;
        executionCount += 1;
    }

    function nextNonce(address account) external view returns (uint256) { return nonces[account]; }

}
