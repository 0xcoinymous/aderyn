// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_RoyaltyClaimSafeRollback10 {
    uint256 public successful; bytes32 public lastAction; mapping(address=>uint256) public nonces; mapping(bytes32=>bool) public failed;

    

    function claimRoyalty(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,address target,bytes calldata payload,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==nonces[signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[signer]=nonce+1; (bool ok,)=target.call(payload); if(!ok){ failed[actionId]=true; } successful += 1; lastAction = actionId;
    }
}
