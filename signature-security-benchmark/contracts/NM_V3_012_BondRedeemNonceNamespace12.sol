// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BondRedeemNonceNamespace12 {
    mapping(bytes32 => uint256) public executed; mapping(address=>mapping(uint256=>uint256)) public chainNonce;

    

    function redeemBySig(address signer,address recipient,address token,address wallet,bytes32 lane,bytes32 market,uint256 sourceChain,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==chainNonce[signer][sourceChain],"wrong source nonce"); bytes32 digest=keccak256(abi.encode(signer,sourceChain,recipient,amount,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        chainNonce[signer][block.chainid]=nonce+1; executed[actionId] += amount;
    }
}
