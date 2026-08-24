// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_KeeperNoOneTimeAuthorizationId28 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public keeperRewards;

    constructor(address signer_) { authorizedSigner = signer_; }

    function performKeeperJob(bytes32 jobId, address keeper, uint256 reward, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(jobId, keeper, reward, authorizationId));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        keeperRewards[keeper] += reward;
    }
}
