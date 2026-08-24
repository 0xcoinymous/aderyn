// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_OracleUpdateSafeNamespace08 is NM_NonceSignerBase {
    
    mapping(bytes32 => uint256) public executed;
    mapping(bytes32 => uint256) public authorityNonces;

    

    

    function updateBySig(address signer, bytes32 authorityHash, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == authorityNonces[authorityHash], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, authorityHash, recipient, amount, actionId, nonce));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        authorityNonces[authorityHash] = nonce + 1;
        executed[actionId] += amount;
    }
}
