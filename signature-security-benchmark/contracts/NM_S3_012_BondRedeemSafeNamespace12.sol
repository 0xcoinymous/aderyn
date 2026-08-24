// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BondRedeemSafeNamespace12 {
    mapping(bytes32 => uint256) public executed; mapping(address=>mapping(address=>mapping(address=>uint256))) public approvalNonce;

    

    function redeemBySig(address signer,address token,address spender,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==approvalNonce[signer][token][spender],"wrong approval nonce"); bytes32 digest=keccak256(abi.encode(signer,token,spender,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        approvalNonce[signer][token][spender]=nonce+1; executed[actionId] += amount;
    }
}
