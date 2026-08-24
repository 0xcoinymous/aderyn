// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_LoanDrawAdversarialSafe16 is NM_NonceSignerBase {
    
    mapping(address => uint256) public nonces;

    

    function invalidate(uint256 newNonce) external { require(newNonce > nonces[msg.sender]); nonces[msg.sender] = newNonce; }

    function drawBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce"); bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce + 1;
    }
}
