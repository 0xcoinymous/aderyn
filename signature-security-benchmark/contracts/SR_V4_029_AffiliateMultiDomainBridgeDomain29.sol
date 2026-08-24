// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AffiliateMultiDomainBridgeDomain29 is SR_ReplayBenchSignerBase {
    mapping(address => uint256) public affiliateCredit;
    mapping(uint256 => mapping(bytes32 => bool)) public processedBySourceChain;

    constructor(address signer_) SR_ReplayBenchSignerBase(signer_) {}

    function finalize(address affiliate, uint256 amount, bytes32 campaign, uint256 sourceChainId, bytes32 messageId, bytes calldata signature) external {
        require(!processedBySourceChain[sourceChainId][messageId], "processed");
        bytes32 digest = keccak256(abi.encode(affiliate, amount, campaign, messageId));
        require(_isAuthorized(digest, signature), "invalid signature");
        processedBySourceChain[sourceChainId][messageId] = true;
        affiliateCredit[affiliate] += amount;
    }
}
