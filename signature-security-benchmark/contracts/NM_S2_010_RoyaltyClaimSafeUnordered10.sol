// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_RoyaltyClaimSafeUnordered10 {
    uint256 public successful; bytes32 public lastAction; mapping(address=>mapping(uint256=>uint256)) public nonceBitmap;

    

    function claimRoyalty(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonceA,uint256 nonceB,uint8 v,bytes32 r,bytes32 s) external {
        uint256 wordA=nonceA>>8; uint256 bitA=uint256(1)<<uint8(nonceA); uint256 wordB=nonceB>>8; uint256 bitB=uint256(1)<<uint8(nonceB); require((nonceBitmap[signer][wordA]&bitA)==0 && (nonceBitmap[signer][wordB]&bitB)==0,"used"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonceA,nonceB));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonceBitmap[signer][wordA]|=bitA; nonceBitmap[signer][wordB]|=bitB; successful += 1; lastAction = actionId;
    }
}
