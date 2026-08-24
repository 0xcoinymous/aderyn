// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SwapQuoteMultiDomainBridgeDomain19 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public swapReceived;
    mapping(uint256 => mapping(bytes32 => bool)) public processedBySourceChain;

    constructor(address signer_) { authorizedSigner = signer_; }

    function finalize(address trader, address tokenOut, uint256 amountOut, bytes32 quoteId, uint256 sourceChainId, bytes32 messageId, bytes calldata signature) external {
        require(!processedBySourceChain[sourceChainId][messageId], "processed");
        bytes32 digest = keccak256(abi.encode(trader, tokenOut, amountOut, quoteId, messageId));
        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");
        processedBySourceChain[sourceChainId][messageId] = true;
        swapReceived[trader] += amountOut;
    }
}
