// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_VaultHarvestAdversarialSafe14 {
    mapping(bytes32=>bool) public usedDigest; uint256 public nonceObservations;

    

    function harvestBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce)); require(!usedDigest[digest],"used");
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        usedDigest[digest]=true; nonceObservations += nonce==0 ? 0 : 1;
    }
}
