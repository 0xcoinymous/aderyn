// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_KeeperSafePrincipalNonce10 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public keeperRewards;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function performKeeperJob(bytes32 jobId, address keeper, uint256 reward, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == nonces[keeper], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(jobId, keeper, reward, nonce));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        nonces[keeper] = nonce + 1;

        keeperRewards[keeper] += reward;
    }
}
