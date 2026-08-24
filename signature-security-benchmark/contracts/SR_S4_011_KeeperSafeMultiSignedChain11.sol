// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_KeeperSafeMultiSignedChain11 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public keeperRewards;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function performKeeperJob(bytes32 jobId, address keeper, uint256 reward, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(jobId, keeper, reward, block.chainid, authorizationId));

        require(_verifySignature(digest, signature), "invalid signature");

        used[authorizationId] = true;

        keeperRewards[keeper] += reward;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
