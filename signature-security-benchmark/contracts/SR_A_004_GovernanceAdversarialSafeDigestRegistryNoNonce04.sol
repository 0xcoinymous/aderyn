// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GovernanceAdversarialSafeDigestRegistryNoNonce04 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(uint256 => uint256) public proposalExecutions;
    mapping(bytes32 => bool) public usedDigest;

    constructor(address wallet_) { wallet = wallet_; }

    function executeProposal(uint256 proposalId, bytes32 actionHash, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(proposalId, actionHash));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        require(!usedDigest[digest], "used");
        usedDigest[digest] = true;

        proposalExecutions[proposalId] += 1;
    }
}
