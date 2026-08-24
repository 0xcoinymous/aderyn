// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BondRedeemNonceResetRollback12 {
    mapping(bytes32 => uint256) public executed; mapping(address=>mapping(bytes32=>bool)) public canceled; mapping(address=>mapping(bytes32=>bool)) public used;

    function setCanceled(address signer,bytes32 id,bool value) external { canceled[signer][id]=value; }

    function redeemBySig(address signer,address recipient,uint256 amount,bytes32 actionId,bytes32 authorizationId,uint8 v,bytes32 r,bytes32 s) external {
        require(!canceled[signer][authorizationId] && !used[signer][authorizationId],"invalid"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,authorizationId));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        used[signer][authorizationId]=true; executed[actionId] += amount;
    }
}
