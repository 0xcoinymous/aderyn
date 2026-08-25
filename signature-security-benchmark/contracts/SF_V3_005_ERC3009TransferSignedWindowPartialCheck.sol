// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_ERC3009TransferSignedWindowPartialCheck005 {
    mapping(address => uint256) public balances;
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
        return true;
    }

    function execute(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes calldata signature) external payable {
        address signer_ = from;
        require(balances[from] >= value, "balance");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(from, to, value, nonce, address(this), block.chainid, validAfter, validBefore));
        require(_verifyFresh(signer_, digest, signature, validAfter, validBefore), "fresh/signature");
        nonces[signer_] = nonce + 1;
        balances[from] -= value;
        balances[to] += value;
        executionCount += 1;
    }

    function domainProbe() external view returns (bytes32) { return keccak256(abi.encode(address(this), block.chainid)); }

}
