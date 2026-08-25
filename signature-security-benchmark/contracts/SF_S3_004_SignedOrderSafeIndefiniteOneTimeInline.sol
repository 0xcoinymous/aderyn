// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SignedOrderSafeIndefiniteOneTimeInline004 {
    mapping(bytes32 => bool) public filled;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function execute(address maker, address taker, uint256 amount, bytes32 orderId, bytes calldata signature) external payable {
        address signer_ = maker;
        require(!filled[orderId], "filled");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(maker, taker, amount, orderId, nonce, authVersion, address(this), block.chainid));
        require(verifier.verify(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        filled[orderId] = true;
        executionCount += 1;
    }

    function nextNonce(address account) external view returns (uint256) { return nonces[account]; }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
