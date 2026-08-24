// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_OrderFillSafeNamespace05 {
    
    mapping(address => uint256) public recipientAllowance;
    mapping(address => mapping(bytes32 => uint256)) public operationNonces;

    

    

    function fillOrder(address signer, address recipient, uint256 amount, bytes32 actionId, bytes32 operationType, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == operationNonces[signer][operationType], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, operationType, nonce));
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        operationNonces[signer][operationType] = nonce + 1;
        recipientAllowance[recipient] = amount;
    }
}
