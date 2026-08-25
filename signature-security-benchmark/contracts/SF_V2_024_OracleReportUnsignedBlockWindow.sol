// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_OracleReportUnsignedBlockWindow024 {
    mapping(bytes32 => uint256) public currentPrice;
    mapping(bytes32 => uint256) public archivedPrice;
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

    function execute(address oracle, bytes32 asset, uint256 price, uint256 validThroughBlock, bytes calldata signature) external payable {
        address signer_ = oracle;
        require(price > 0, "price");
        uint256 nonce = nonces[signer_];
        bytes32 digest = _digest(abi.encode(oracle, asset, price, nonce));
        require(_signatureOk(signer_, digest, signature), "signature");
        require(block.number <= validThroughBlock, "late block");
        nonces[signer_] = nonce + 1;
        currentPrice[asset] = price;
        executionCount += 1;
    }

    function domainProbe() external view returns (bytes32) { return keccak256(abi.encode(address(this), block.chainid)); }

}
