// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_RFQFillSafeRollback08 {
    
    mapping(bytes32 => uint256) public executed;
    mapping(address => uint256) public nonces;

    

    function invalidateNonce(uint256 newNonce) external { require(newNonce > nonces[msg.sender], "must increase"); nonces[msg.sender] = newNonce; }

    function fillRfq(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, uint256 newNonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        executed[actionId] += amount;
    }
}
