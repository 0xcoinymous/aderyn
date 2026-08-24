// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_TicketMultiDomainBridgeDomain39 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public ticketPaid;
    mapping(uint256 => mapping(bytes32 => bool)) public processedBySourceChain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function finalize(address user, uint256 amount, bytes32 ticketId, uint256 sourceChainId, bytes32 messageId, uint8 v, bytes32 r, bytes32 s) external {
        require(!processedBySourceChain[sourceChainId][messageId], "processed");
        bytes32 digest = keccak256(abi.encode(user, amount, ticketId, messageId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        processedBySourceChain[sourceChainId][messageId] = true;
        ticketPaid[user] += amount;
    }
}
