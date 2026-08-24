// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_KeeperMultiDomainCrossChain24 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public keeperRewards;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(bytes32 jobId, address keeper, uint256 reward, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[keeper], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(jobId, keeper, reward, nonce));
        require(_verifySignature(digest, signature), "invalid signature");
        nonces[keeper] = nonce + 1;
        keeperRewards[keeper] += reward;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
