// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SwapQuoteCheckedNotConsumedDigestIdMismatch15 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public swapReceived;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function executeQuote(address trader, address tokenOut, uint256 amountOut, bytes32 quoteId, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(trader, tokenOut, amountOut, quoteId, authorizationId));

        require(!used[digest], "used");

        require(_isAuthorized(digest, signature), "invalid signature");

        used[authorizationId] = true;

        swapReceived[trader] += amountOut;
    }
}
