// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GovernanceCheckedNotConsumedEventOnly16 {
    address public immutable authorizedSigner;
    mapping(uint256 => uint256) public proposalExecutions;
    mapping(bytes32 => bool) public used; event AuthorizationConsumed(bytes32 indexed id);

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeProposal(uint256 proposalId, bytes32 actionHash, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(proposalId, actionHash, authorizationId));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        emit AuthorizationConsumed(authorizationId);

        proposalExecutions[proposalId] += 1;
    }
}
