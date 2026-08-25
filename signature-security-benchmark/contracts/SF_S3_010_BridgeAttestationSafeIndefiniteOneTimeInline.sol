// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_BridgeAttestationSafeIndefiniteOneTimeInline010 {
    mapping(bytes32 => bool) public released;
    mapping(address => uint256) public bridged;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function execute(address validator, bytes32 messageId, address recipient, uint256 amount, bytes calldata signature) external payable {
        address signer_ = validator;
        require(!released[messageId], "released");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(validator, messageId, recipient, amount, nonce, authVersion, address(this), block.chainid));
        require(verifier.verify(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        released[messageId] = true;
        bridged[recipient] += amount;
        executionCount += 1;
    }

    function nextNonce(address account) external view returns (uint256) { return nonces[account]; }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
