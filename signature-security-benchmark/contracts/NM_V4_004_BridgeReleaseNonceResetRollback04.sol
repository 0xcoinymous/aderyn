// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BridgeReleaseNonceResetRollback04 is NM_NonceSignerBase {
    
    mapping(bytes32 => bool) public completed;
    mapping(address => uint256) public nonces; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(bytes32 => bool)) public canceled; mapping(address => uint256) public sessionCounters;

    

    

    function releaseBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external  {
        uint256 word = nonce >> 8; uint256 bitPos = uint8(nonce); uint256 bit = uint256(1) << bitPos; require((nonceBitmap[signer][word] & bit) == 0, "used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        nonceBitmap[signer][word] |= uint256(1) << ((bitPos + 1) & 255);
        completed[actionId] = true;
    }
}
