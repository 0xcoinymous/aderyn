// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_OracleUpdateNonceResetRollback08 is NM_NonceSignerBase {
    
    mapping(bytes32 => uint256) public executed;
    mapping(address => uint256) public nonces; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(bytes32 => bool)) public canceled; mapping(address => uint256) public sessionCounters;

    

    function resetSession(address signer, uint256 epoch) external { sessionCounters[signer] = epoch; }

    function updateBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == sessionCounters[signer], "wrong epoch");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        sessionCounters[signer] = nonce + 1;
        executed[actionId] += amount;
    }
}
