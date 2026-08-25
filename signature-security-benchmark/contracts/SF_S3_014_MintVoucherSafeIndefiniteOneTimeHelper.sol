// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_MintVoucherSafeIndefiniteOneTimeHelper014 {
    mapping(uint256 => address) public ownerOf;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;


    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature
    ) internal view returns (bool) {
        if (SF_FreshnessBenchLib.recover(digest, signature) != signer_) return false;

        return true;
    }

    function execute(address issuer, address recipient, uint256 tokenId, bytes calldata signature) external payable {
        address signer_ = issuer;
        require(ownerOf[tokenId] == address(0), "minted");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(issuer, recipient, tokenId, nonce, authVersion, address(this), block.chainid));
        require(_verifyFresh(signer_, digest, signature), "fresh/signature");
        nonces[signer_] = nonce + 1;
        ownerOf[tokenId] = recipient;
        executionCount += 1;
    }

    function domainProbe() external view returns (bytes32) { return keccak256(abi.encode(address(this), block.chainid)); }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
