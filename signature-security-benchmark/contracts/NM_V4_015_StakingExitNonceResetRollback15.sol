// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_StakingExitNonceResetRollback15 {
    mapping(address => uint256) public processed; mapping(address=>uint256) public nonces;

    

    function exitBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,address target,bytes calldata payload,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==nonces[signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        nonces[signer]=nonce+1; try NM_IAction(target).run(payload) returns(bool ok){ require(ok,"failed"); } catch { revert("downstream failed"); } processed[recipient] += amount;
    }
}
