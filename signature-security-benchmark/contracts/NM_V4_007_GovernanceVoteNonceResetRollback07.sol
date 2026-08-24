// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_GovernanceVoteNonceResetRollback07 {
    
    address public lastRecipient; uint256 public successful;
    mapping(address => uint256) public nonces; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(bytes32 => bool)) public canceled; mapping(address => uint256) public sessionCounters;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function voteBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external  {
        require(!authorizationState[signer][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, authorizationId));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        authorizationState[signer][authorizationId] = true;
        delete authorizationState[signer][authorizationId];
        lastRecipient = recipient; successful += 1;
    }
}
