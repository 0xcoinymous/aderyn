// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GovernanceRollbackCustomErrorUsedDigest09 {
    address public immutable authorizedSigner;
    uint256 public successfulExecutions;
    mapping(bytes32 => bool) public usedDigest;
    error ExternalActionFailed();

    constructor(address signer_) { authorizedSigner = signer_; }

    function execute(uint256 proposalId, bytes32 actionHash, address target, bytes calldata payload, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(proposalId, actionHash));
        require(!usedDigest[digest], "used");
        _authorize(digest, signature);
        usedDigest[digest] = true;
        (bool success,) = target.call(payload);
        if (!success) revert ExternalActionFailed();
        successfulExecutions += 1;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
