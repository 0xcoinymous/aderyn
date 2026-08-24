// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_OracleUpdateNonceNamespace08 {
    
    mapping(bytes32 => uint256) public executed;
    mapping(address => uint256) public nonces; mapping(address => uint256) public relayerNonces; mapping(address => uint256) public identityNonces; mapping(address => mapping(bytes32 => uint256)) public operationNonces; mapping(address => mapping(address => mapping(address => uint256))) public approvalNonces;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function updateBySig(address signer, address cosigner, address identity, bytes32 accountHash, address recipient, address token, address spender, address alternateSigner, uint256 amount, bytes32 actionId, bytes32 operationType, bytes32 alternateOperationType, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        nonces[alternateSigner] = nonce + 1;
        executed[actionId] += amount;
    }
}
