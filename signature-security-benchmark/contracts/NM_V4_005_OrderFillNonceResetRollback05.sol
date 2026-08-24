// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_OrderFillNonceResetRollback05 {
    
    mapping(address => uint256) public recipientAllowance;
    mapping(address => uint256) public nonces; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(bytes32 => bool)) public canceled; mapping(address => uint256) public sessionCounters;

    

    function cancel(bytes32 authorizationId) external { canceled[msg.sender][authorizationId] = true; }

    function fillOrder(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external  {
        require(!authorizationState[signer][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, authorizationId));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        authorizationState[signer][authorizationId] = true;
        recipientAllowance[recipient] = amount;
    }
}
