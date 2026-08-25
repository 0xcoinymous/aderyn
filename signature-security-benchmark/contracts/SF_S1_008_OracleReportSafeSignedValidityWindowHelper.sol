// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_OracleReportSafeSignedValidityWindowHelper008 {
    mapping(bytes32 => uint256) public currentPrice;
    mapping(bytes32 => uint256) public archivedPrice;
    mapping(address => uint256) public nonces;

    
    uint256 public executionCount;


    function _verifyFresh(
        address signer_,
        bytes32 digest,
        bytes calldata signature, uint256 validAfter, uint256 validBefore
    ) internal view returns (bool) {
        if (SF_FreshnessBenchLib.recover(digest, signature) != signer_) return false;
        if (!(block.timestamp >= validAfter)) return false;
        if (!(block.timestamp <= validBefore)) return false;
        return true;
    }

    function execute(address oracle, bytes32 asset, uint256 price, uint256 validAfter, uint256 validBefore, bytes calldata signature) external payable {
        address signer_ = oracle;
        require(price > 0, "price");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(oracle, asset, price, nonce, address(this), block.chainid, validAfter, validBefore));
        require(_verifyFresh(signer_, digest, signature, validAfter, validBefore), "fresh/signature");
        nonces[signer_] = nonce + 1;
        currentPrice[asset] = price;
        executionCount += 1;
    }

    function domainProbe() external view returns (bytes32) { return keccak256(abi.encode(address(this), block.chainid)); }

}
