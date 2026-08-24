// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BatchPaymentSafeUnordered11 {
    mapping(address => uint256) public processed; mapping(address=>mapping(bytes32=>bool)) public authorizationState; mapping(address=>mapping(bytes32=>bool)) public canceled;

    function cancel(bytes32 id) external { canceled[msg.sender][id]=true; }

    function batchPayBySig(address signer,address recipient,uint256 amount,bytes32 actionId,bytes32 authorizationId,uint8 v,bytes32 r,bytes32 s) external {
        require(!authorizationState[signer][authorizationId] && !canceled[signer][authorizationId],"invalid"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,authorizationId));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        authorizationState[signer][authorizationId]=true; processed[recipient] += amount;
    }
}
