// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./SF_FreshnessBenchLib.sol";

contract SF_SignedClaimSafeIndefiniteOneTimeInline007 {
    mapping(bytes32 => bool) public claimed;
    mapping(address => uint256) public rewards;
    mapping(address => uint256) public nonces;

    mapping(address => uint256) public authorizationVersion;
    uint256 public executionCount;


    function execute(address claimant, bytes32 claimId, uint256 amount, bytes calldata signature) external payable {
        address signer_ = claimant;
        require(!claimed[claimId], "claimed");
        uint256 authVersion = authorizationVersion[signer_];
        uint256 nonce = nonces[signer_];
        bytes32 digest = keccak256(abi.encode(claimant, claimId, amount, nonce, authVersion, address(this), block.chainid));
        require(SF_FreshnessBenchLib.recover(digest, signature) == signer_, "signature");

        nonces[signer_] = nonce + 1;
        claimed[claimId] = true;
        rewards[claimant] += amount;
        executionCount += 1;
    }

    function nonceOf(address account) external view returns (uint256) { return nonces[account]; }

    function invalidateStandingAuthorizations() external { authorizationVersion[msg.sender] += 1; }

}
