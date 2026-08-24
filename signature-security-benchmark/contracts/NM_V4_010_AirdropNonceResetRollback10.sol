// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AirdropNonceResetRollback10 {
    uint256 public successful; bytes32 public lastAction; mapping(address=>mapping(uint256=>uint256)) public nonceBitmap;

    function invalidate(address signer,uint256 word,uint256 mask,bool clear) external { if(clear) nonceBitmap[signer][word] &= ~mask; else nonceBitmap[signer][word] |= mask; }

    function claimBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,address target,bytes calldata payload,uint8 v,bytes32 r,bytes32 s) external {
        uint256 word=nonce>>8; uint256 bit=uint256(1)<<uint8(nonce); require((nonceBitmap[signer][word]&bit)==0,"used"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonceBitmap[signer][word]|=bit; successful += 1; lastAction = actionId;
    }
}
