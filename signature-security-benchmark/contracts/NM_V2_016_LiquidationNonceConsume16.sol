// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_LiquidationNonceConsume16 {
    mapping(bytes32 => uint256) public executed; mapping(address=>uint256) public nonces; mapping(address=>bool) public consumedFlag;

    

    function liquidateBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,bool directCaller,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==nonces[signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        bool consumed=consumedFlag[signer]; consumed=true; require(consumed); executed[actionId] += amount;
    }
}
