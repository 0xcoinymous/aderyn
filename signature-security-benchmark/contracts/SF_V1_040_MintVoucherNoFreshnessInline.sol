// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_MintVoucherNoFreshnessInline040 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;
    SF_IFreshnessVerifier public immutable verifier;

    constructor(SF_IFreshnessVerifier verifier_) {
        verifier = verifier_;
    }

    function execute(address issuer, address recipient, uint256 tokenId, bytes calldata signature) external payable {
        address signer_ = issuer;
        require(ownerOf[tokenId] == address(0), "minted");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(issuer, recipient, tokenId, nonce, address(this), block.chainid));
        require(verifier.verify(signer_, digest, signature), "signature");

        nonces[signer_] = nonce + 1;
        ownerOf[tokenId] = recipient;
        executionCount += 1;
    }

    function domainProbe() external view returns (bytes32) { return keccak256(abi.encode(address(this), block.chainid)); }

}
