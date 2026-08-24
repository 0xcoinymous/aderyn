// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RfqCheckedNotConsumedWrongPrincipal22 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(bytes32 => uint256) public rfqFilled;
    mapping(address => mapping(bytes32 => bool)) public usedBySigner;

    constructor(address wallet_) { wallet = wallet_; }

    function fillRfq(bytes32 quoteId, address maker, address taker, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedBySigner[maker][authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(quoteId, maker, taker, amount, authorizationId));

        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");

        usedBySigner[msg.sender][authorizationId] = true;

        rfqFilled[quoteId] += amount;
    }
}
