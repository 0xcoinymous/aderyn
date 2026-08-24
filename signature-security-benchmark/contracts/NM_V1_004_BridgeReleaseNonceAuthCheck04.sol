// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BridgeReleaseNonceAuthCheck04 is NM_NonceSignerBase {
    
    mapping(bytes32 => bool) public completed;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    mapping(address => uint256) public sequences;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;
    mapping(address => uint256) public sessionCounters;

    

    

    function releaseBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, bytes32 guardId, uint256 sequence, uint256 sessionSeed, uint8 v, bytes32 r, bytes32 s) external  {
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, authorizationId));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        authorizationState[signer][authorizationId] = true;
        completed[actionId] = true;
    }
}
