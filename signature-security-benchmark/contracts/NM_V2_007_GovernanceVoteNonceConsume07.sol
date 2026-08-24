// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_GovernanceVoteNonceConsume07 {
    
    address public lastRecipient; uint256 public successful;
    mapping(address => uint256) public nonces; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => uint256) public sequences; uint256 public executionCounter; event AuthorizationObserved(address indexed signer, bytes32 indexed id);

    

    

    function voteBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, uint256 sequence, bool consumeNonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(sequence == sequences[signer], "wrong sequence");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, sequence));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        lastRecipient = recipient; successful += 1;
    }
}
