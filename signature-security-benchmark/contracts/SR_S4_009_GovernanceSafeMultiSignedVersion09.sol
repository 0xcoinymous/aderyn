// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GovernanceSafeMultiSignedVersion09 {
    address public immutable authorizedSigner;
    mapping(uint256 => uint256) public proposalExecutions;
    uint256 public constant PROTOCOL_VERSION = 7; mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeProposal(uint256 proposalId, bytes32 actionHash, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(proposalId, actionHash, PROTOCOL_VERSION, authorizationId));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        used[authorizationId] = true;

        proposalExecutions[proposalId] += 1;
    }
}
