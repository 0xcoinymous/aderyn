// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_KeeperReportUnsignedBlockWindow051 {
    mapping(uint256 => uint64) public latestRound;
    mapping(bytes32 => bool) public archivedReport;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address keeper, uint256 upkeepId, uint64 round, bytes32 reportHash, uint256 validThroughBlock, bytes calldata signature) external payable {
        address signer_ = keeper;
        require(reportHash != bytes32(0), "report");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(keeper, upkeepId, round, reportHash, nonce));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.number <= validThroughBlock, "late block");
        nonces[signer_] = nonce + 1;
        latestRound[upkeepId] = round;
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
