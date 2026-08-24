// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_WithdrawalNonceConsume02 is NM_NonceSignerBase {
    
    uint256 public operationCount; bytes32 public lastAction;
    mapping(address => uint256) public nonces; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => uint256) public sequences; uint256 public executionCounter; event AuthorizationObserved(address indexed signer, bytes32 indexed id);

    

    

    function withdrawBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, uint256 sequence, bool consumeNonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce;
        operationCount += 1; lastAction = actionId;
    }
}
