// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_ERC3009TransferSafeMonotonicRoundHelper002 {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public latestFreshness;

    uint256 public executionCount;


    function _verifyOnly(address signer_, bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SF_FreshnessBenchLib.recover(digest, signature) == signer_;
    }

    function execute(address from, address to, uint256 value, uint64 round, bytes calldata signature) external payable {
        address signer_ = from;
        require(balances[from] >= value, "balance");
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(from, to, value, nonce, address(this), block.chainid, round));
        require(_verifyOnly(signer_, digest, signature), "signature");
        require(uint256(round) > latestFreshness[signer_], "old round");
        latestFreshness[signer_] = uint256(round);
        nonces[signer_] = nonce + 1;
        balances[from] -= value;
        balances[to] += value;
        executionCount += 1;
    }

    function domainProbe() external view returns (bytes32) { return keccak256(abi.encode(address(this), block.chainid)); }

}
