// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AdminGrantNoOneTimeSignedNonce10 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public roles;

    constructor(address signer_) { authorizedSigner = signer_; }

    function grantBySig(address account, uint256 role, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(account, role, nonce));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        roles[account] = role;
    }
}
