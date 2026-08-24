// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_KeeperRollbackTryCatchRethrowUsedDigest13 is SR_ReplayBenchSignerBase {
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedDigest;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function execute(bytes32 jobId, address keeper, uint256 reward, address target, bytes calldata payload, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(jobId, keeper, reward));
        require(!usedDigest[digest], "used");
        require(_isAuthorized(digest, signature), "invalid signature");
        usedDigest[digest] = true;
        try SR_IReplayBenchAction(target).run(payload) returns (bool ok) {
            require(ok, "action returned false");
        } catch {
            revert("action reverted");
        }
        successfulExecutions += 1;
    }
}
