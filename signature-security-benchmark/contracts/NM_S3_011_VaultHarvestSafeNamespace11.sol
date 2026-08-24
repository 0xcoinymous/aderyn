// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_VaultHarvestSafeNamespace11 {
    mapping(address => uint256) public processed; mapping(bytes32=>uint256) public authorityNonce;

    

    function harvestBySig(address signer,bytes32 authorityHash,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==authorityNonce[authorityHash],"wrong authority nonce"); bytes32 digest=keccak256(abi.encode(signer,authorityHash,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        authorityNonce[authorityHash]=nonce+1; processed[recipient] += amount;
    }
}
