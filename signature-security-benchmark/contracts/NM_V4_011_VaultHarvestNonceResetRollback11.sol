// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_VaultHarvestNonceResetRollback11 {
    mapping(address => uint256) public processed; mapping(address=>uint8) public sequence;

    

    function harvestBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint8 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==sequence[signer],"wrong sequence"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        unchecked { sequence[signer]=nonce+1; } processed[recipient] += amount;
    }
}
