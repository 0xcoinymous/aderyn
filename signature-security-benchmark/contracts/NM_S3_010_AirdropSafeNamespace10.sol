// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AirdropSafeNamespace10 {
    uint256 public successful; bytes32 public lastAction; mapping(address=>uint256) public identityNonce;

    

    function claimBySig(address signer,address identity,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==identityNonce[identity],"wrong identity nonce"); bytes32 digest=keccak256(abi.encode(signer,identity,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        identityNonce[identity]=nonce+1; successful += 1; lastAction = actionId;
    }
}
