// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_StakingExitNonceConsume15 {
    mapping(address => uint256) public processed; mapping(address=>uint256) public nonces; mapping(address=>uint256) public lastSeen; mapping(address=>mapping(uint256=>uint256)) public nonceBitmap; mapping(address=>mapping(uint256=>uint256)) public observedBitmap;

    

    function exitBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,bool directCaller,uint8 v,bytes32 r,bytes32 s) external {
        uint256 word=nonce>>8; uint256 bit=uint256(1)<<uint8(nonce); require((nonceBitmap[signer][word]&bit)==0,"used"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        observedBitmap[signer][word]|=bit; processed[recipient] += amount;
    }
}
