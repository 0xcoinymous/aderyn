// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_DelegatedVoteAdversarialSafeErc1271Safe09 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(uint256 => uint256) public proposalVotes;
    mapping(bytes32 => bool) public used;

    constructor(address wallet_) { wallet = wallet_; }

    function voteBySig(address voter, uint256 proposalId, uint256 weight, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(voter, proposalId, weight, wallet, authorizationId));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        used[authorizationId] = true;

        proposalVotes[proposalId] += weight;
    }
}
