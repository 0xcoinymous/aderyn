// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_DelegatedExecutionSafeIndefiniteRevocableVersion015 {
    mapping(address => uint256) public delegatedCalls;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;


    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address principal, address target, uint256 value, bytes calldata data, bytes calldata signature) external payable {
        address signer_ = principal;
        require(target != address(0), "target");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(principal, target, value, keccak256(data), nonce, authVersion));
        require(_signatureOk(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        (bool ok,) = target.call{value: value}(data);
        require(ok, "call");
        delegatedCalls[principal] += 1;
        executionCount += 1;
    }

    function executions() external view returns (uint256) { return executionCount; }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
