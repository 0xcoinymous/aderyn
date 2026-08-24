// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AdminGrantNonceNamespace09 {
    mapping(address => uint256) public credits; mapping(address=>uint256) public nonces;

    

    function grantBySig(address signer,address recipient,address token,address wallet,bytes32 lane,bytes32 market,uint256 sourceChain,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==nonces[signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[tx.origin]=nonce+1; credits[recipient] += amount;
    }
}
