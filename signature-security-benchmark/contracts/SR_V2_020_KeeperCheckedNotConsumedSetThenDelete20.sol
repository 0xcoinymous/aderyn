// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_KeeperCheckedNotConsumedSetThenDelete20 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public keeperRewards;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function performKeeperJob(bytes32 jobId, address keeper, uint256 reward, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(jobId, keeper, reward, authorizationId));

        _authorize(digest, signature);

        used[authorizationId] = true;
        delete used[authorizationId];

        keeperRewards[keeper] += reward;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
