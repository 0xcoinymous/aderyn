// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_StakingExitMultiDomainModuleNamespace16 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public exitedStake;
    mapping(bytes32 => mapping(address => uint256)) public moduleNonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(address staker, uint256 amount, uint256 validatorId, bytes32 moduleId, uint256 nonce, bytes calldata signature) external {
        require(nonce == moduleNonces[moduleId][staker], "wrong nonce");

        // Vulnerable: moduleId selects an independent nonce namespace but is not signed.
        bytes32 digest = keccak256(abi.encode(staker, amount, validatorId, nonce));
        _authorize(digest, signature);

        moduleNonces[moduleId][staker] = nonce + 1;
        exitedStake[staker] += amount;
    }

    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
