// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_OffchainQuoteUnsignedValidityWindow047 {
    mapping(bytes32 => bool) public consumedQuote;
    mapping(address => uint256) public quotedAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature, uint256 validAfter, uint256 validBefore
    ) internal view returns (bool) {
        if (!verifier.verify(signer_, digest, signature)) return false;
        if (!(block.timestamp >= validAfter)) return false;
        if (!(block.timestamp <= validBefore)) return false;
        return true;
    }

    function execute(address quoter, address user, bytes32 quoteId, uint256 amountOut, uint256 validAfter, uint256 validBefore, bytes calldata signature) external payable {
        address signer_ = quoter;
        require(!consumedQuote[quoteId], "used");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(quoter, user, quoteId, amountOut, nonce, address(this), block.chainid));
        require(_verifyFresh(signer_, digest, signature, validAfter, validBefore), "fresh/signature");
        nonces[signer_] = nonce + 1;
        consumedQuote[quoteId] = true;
        quotedAmount[user] = amountOut;
        executionCount += 1;
    }

    function nextNonce(address account) external view returns (uint256) { return nonces[account]; }

}
