// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SwapQuoteSafeAuthorizationId08 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public swapReceived;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeQuote(address trader, address tokenOut, uint256 amountOut, bytes32 quoteId, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(trader, tokenOut, amountOut, quoteId, authorizationId));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        usedAuthorization[authorizationId] = true;

        swapReceived[trader] += amountOut;
    }
}
