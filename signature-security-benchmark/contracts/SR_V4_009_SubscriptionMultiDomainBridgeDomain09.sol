// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SubscriptionMultiDomainBridgeDomain09 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(address => uint256) public charged;
    mapping(uint256 => mapping(bytes32 => bool)) public processedBySourceChain;

    constructor(address wallet_) { wallet = wallet_; }

    function finalize(address subscriber, uint256 amount, uint256 period, uint256 sourceChainId, bytes32 messageId, bytes calldata signature) external {
        require(!processedBySourceChain[sourceChainId][messageId], "processed");
        bytes32 digest = keccak256(abi.encode(subscriber, amount, period, messageId));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        processedBySourceChain[sourceChainId][messageId] = true;
        charged[subscriber] += amount;
    }
}
