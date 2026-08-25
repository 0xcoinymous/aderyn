// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_TemporaryApprovalSignedTimestampUnitMismatch039 {
    mapping(address => mapping(address => uint256)) public approvedAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address owner, address delegate, uint256 amount, uint256 issuedAtMs, bytes calldata signature) external payable {
        address signer_ = owner;
        require(delegate != address(0), "delegate");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(owner, delegate, amount, nonce, issuedAtMs));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.timestamp <= issuedAtMs + 300, "stale");
        nonces[signer_] = nonce + 1;
        approvedAmount[owner][delegate] = amount;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

}
