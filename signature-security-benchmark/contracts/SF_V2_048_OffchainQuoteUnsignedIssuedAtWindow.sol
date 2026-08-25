// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_OffchainQuoteUnsignedIssuedAtWindow048 {
    mapping(bytes32 => bool) public consumedQuote;
    mapping(address => uint256) public quotedAmount;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function _digest(bytes memory payload) internal view returns (bytes32) {
        return keccak256(abi.encode(payload, address(this), block.chainid));
    }

    function _signatureOk(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return verifier.verify(signer_, digest, signature);
    }

    function execute(address quoter, address user, bytes32 quoteId, uint256 amountOut, uint256 issuedAt, bytes calldata signature) external payable {
        address signer_ = quoter;
        require(!consumedQuote[quoteId], "used");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(quoter, user, quoteId, amountOut, nonce));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(issuedAt <= block.timestamp, "future");
        require(block.timestamp - issuedAt <= 300, "stale");
        nonces[signer_] = nonce + 1;
        consumedQuote[quoteId] = true;
        quotedAmount[user] = amountOut;
        executionCount += 1;
    }

    function nextNonce(address account) external view returns (uint256) { return nonces[account]; }

}
