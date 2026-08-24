// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AdminGrantSafeNamespace09 {
    mapping(address => uint256) public credits; mapping(address=>mapping(bytes32=>uint256)) public laneNonce;

    

    function grantBySig(address signer,address recipient,uint256 amount,bytes32 actionId,bytes32 lane,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==laneNonce[signer][lane],"wrong lane nonce"); bytes32 digest=keccak256(abi.encode(signer,lane,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        laneNonce[signer][lane]=nonce+1; credits[recipient] += amount;
    }
}
