// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_MintVoucherUnsignedBlockWindow042 {
    mapping(uint256 => address) public ownerOf;
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

    function execute(address issuer, address recipient, uint256 tokenId, uint256 validThroughBlock, bytes calldata signature) external payable {
        address signer_ = issuer;
        require(ownerOf[tokenId] == address(0), "minted");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(issuer, recipient, tokenId, nonce));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.number <= validThroughBlock, "late block");
        nonces[signer_] = nonce + 1;
        ownerOf[tokenId] = recipient;
        executionCount += 1;
    }

    function domainProbe() external view returns (bytes32) { return keccak256(abi.encode(address(this), block.chainid)); }

}
