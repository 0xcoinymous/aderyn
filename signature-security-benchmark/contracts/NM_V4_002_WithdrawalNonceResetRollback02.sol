// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_WithdrawalNonceResetRollback02 {
    
    uint256 public operationCount; bytes32 public lastAction;
    mapping(address => uint256) public nonces; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(bytes32 => bool)) public canceled; mapping(address => uint256) public sessionCounters;

    

    function invalidateNonce(uint256 newNonce) external { nonces[msg.sender] = newNonce; }

    function withdrawBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        operationCount += 1; lastAction = actionId;
    }
}
