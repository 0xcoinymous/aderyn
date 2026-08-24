// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AccountRecoveryAdversarialSafe08 is NM_NonceSignerBase {
    
    mapping(address => uint256) public sequence;

    

    

    function recoverAccount(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce > sequence[signer], "stale"); bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        sequence[signer] = nonce;
    }
}
