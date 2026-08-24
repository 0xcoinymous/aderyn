// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_VaultHarvestNonceAuthCheck11 {
    mapping(address => uint256) public processed; mapping(address=>uint256) public nonces;

    

    function harvestBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint256 expectedNonce,bool legacy,uint8 v,bytes32 r,bytes32 s) external {
        require(legacy || nonce == nonces[signer], "wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce,legacy));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[signer]=nonce+1; processed[recipient] += amount;
    }
}
