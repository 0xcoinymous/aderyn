// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AdminGrantSafePrincipalNonce04 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public roles;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function grantBySig(address account, uint256 role, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[account], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(account, role, nonce));

        require(_verifySignature(digest, signature), "invalid signature");

        nonces[account] = nonce + 1;

        roles[account] = role;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
