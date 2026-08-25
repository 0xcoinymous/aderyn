// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_KeeperReportNoFreshnessInline049 {
    mapping(uint256 => uint64) public latestRound;
    mapping(bytes32 => bool) public archivedReport;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function execute(address keeper, uint256 upkeepId, uint64 round, bytes32 reportHash, bytes calldata signature) external payable {
        address signer_ = keeper;
        require(reportHash != bytes32(0), "report");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(keeper, upkeepId, round, reportHash, nonce, address(this), block.chainid));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");

        nonces[signer_] = nonce + 1;
        latestRound[upkeepId] = round;
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
