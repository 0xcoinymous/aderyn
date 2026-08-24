// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BondRedeemSafeSequential12 {
    mapping(bytes32 => uint256) public executed; mapping(address=>uint256) public sequence;

    

    function redeemBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce>sequence[signer],"stale sequence"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        sequence[signer]=nonce; executed[actionId] += amount;
    }
}
