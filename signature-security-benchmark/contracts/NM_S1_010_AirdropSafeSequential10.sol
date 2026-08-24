// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";
contract NM_AirdropSafeSequential10 { uint256 public successful; bytes32 public lastAction; mapping(address=>uint256) public nonces; modifier currentNonce(address signer,uint256 nonce){ require(nonce==nonces[signer],"wrong nonce"); _; nonces[signer]=nonce+1; } function claimBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external currentNonce(signer,nonce) { bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce)); require(NM_NonceBenchLib.recoverChecked(digest,v,r,s)==signer,"invalid signature"); successful += 1; lastAction = actionId; } }
