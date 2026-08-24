// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BatchPaymentSafeRollback11 {
    mapping(address => uint256) public processed; mapping(address=>uint256) public nonces; mapping(bytes32=>bool) public failed;

    function invalidate(uint256 newNonce) external { uint256 old=nonces[msg.sender]; require(newNonce>old && newNonce-old<=65535,"invalid jump"); nonces[msg.sender]=newNonce; }

    function batchPayBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint256 newNonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==nonces[signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[signer]=nonce+1; processed[recipient] += amount;
    }
}
