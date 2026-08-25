// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_TemporaryApprovalSafeIndefiniteOneTimeInline013 {
    mapping(address => mapping(address => uint256)) public approvedAmount;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;


    function execute(address owner, address delegate, uint256 amount, bytes calldata signature) external payable {
        address signer_ = owner;
        require(delegate != address(0), "delegate");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(owner, delegate, amount, nonce, authVersion, address(this), block.chainid));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");

        nonces[signer_] = nonce + 1;
        approvedAmount[owner][delegate] = amount;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
