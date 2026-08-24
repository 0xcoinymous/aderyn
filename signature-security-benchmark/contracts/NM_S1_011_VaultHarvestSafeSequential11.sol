// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_VaultHarvestSafeSequential11 {
    mapping(address=>uint256) public nonces; mapping(address=>uint256) public credits;

    

    function harvestBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,bool allowed,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==nonces[signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce,allowed));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[signer]=nonce+1; if(allowed){ credits[recipient]+=amount; }
    }
}
