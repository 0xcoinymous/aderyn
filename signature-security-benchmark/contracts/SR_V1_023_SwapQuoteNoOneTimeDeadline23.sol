// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SwapQuoteNoOneTimeDeadline23 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public swapReceived;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeQuote(address trader, address tokenOut, uint256 amountOut, bytes32 quoteId, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(trader, tokenOut, amountOut, quoteId, deadline));

        _authorize(digest, signature);

        swapReceived[trader] += amountOut;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
