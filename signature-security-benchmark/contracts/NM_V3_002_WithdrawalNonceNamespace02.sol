// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_WithdrawalNonceNamespace02 {
    
    uint256 public operationCount; bytes32 public lastAction;
    mapping(address => uint256) public nonces; mapping(address => uint256) public relayerNonces; mapping(address => uint256) public identityNonces; mapping(address => mapping(bytes32 => uint256)) public operationNonces; mapping(address => mapping(address => mapping(address => uint256))) public approvalNonces;

    

    

    function withdrawBySig(address signer, address cosigner, address identity, bytes32 accountHash, address recipient, address token, address spender, address alternateSigner, uint256 amount, bytes32 actionId, bytes32 operationType, bytes32 alternateOperationType, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        nonces[recipient] = nonce + 1;
        operationCount += 1; lastAction = actionId;
    }
}
