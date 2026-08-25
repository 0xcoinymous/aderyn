// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_KeeperReportSafeMonotonicRoundHelper017 {
    mapping(uint256 => uint64) public latestRound;
    mapping(bytes32 => bool) public archivedReport;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _verifyOnly(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return verifier.verify(signer_, digest, signature);
    }

    function execute(address keeper, uint256 upkeepId, uint64 round, bytes32 reportHash, uint64 round, bytes calldata signature) external payable {
        address signer_ = keeper;
        require(reportHash != bytes32(0), "report");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(keeper, upkeepId, round, reportHash, nonce, address(this), block.chainid, round));
        require(_verifyOnly(signer_, digest, signature), "signature");
        require(uint256(round) > latestFreshness[signer_], "old round");
        latestFreshness[signer_] = uint256(round);
        nonces[signer_] = nonce + 1;
        latestRound[upkeepId] = round;
        executionCount += 1;
    }

    function hasExecuted() external view returns (bool) { return executionCount != 0; }

}
