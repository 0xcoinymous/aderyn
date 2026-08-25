// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SignedOrderSignedTimestampUnitMismatch012 {
    mapping(bytes32 => bool) public filled;
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

    function execute(address maker, address taker, uint256 amount, bytes32 orderId, uint256 issuedAtMs, bytes calldata signature) external payable {
        address signer_ = maker;
        require(!filled[orderId], "filled");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(maker, taker, amount, orderId, nonce, issuedAtMs));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.timestamp <= issuedAtMs + 300, "stale");
        nonces[signer_] = nonce + 1;
        filled[orderId] = true;
        executionCount += 1;
    }

    function nextNonce(address account) external view returns (uint256) { return nonces[account]; }

}
