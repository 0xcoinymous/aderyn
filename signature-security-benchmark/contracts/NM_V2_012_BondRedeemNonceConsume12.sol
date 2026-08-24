// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BondRedeemNonceConsume12 {
    mapping(bytes32 => uint256) public executed; mapping(address=>uint256) public nonces; mapping(address=>uint256) public lastSeen; mapping(address=>mapping(uint256=>uint256)) public nonceBitmap; mapping(address=>mapping(uint256=>uint256)) public observedBitmap;

    

    function redeemBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,bool directCaller,uint8 v,bytes32 r,bytes32 s) external {
        require(nonces[signer] != type(uint256).max,"disabled"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        if(directCaller){ nonces[signer]=nonce+1; } executed[actionId] += amount;
    }
}
