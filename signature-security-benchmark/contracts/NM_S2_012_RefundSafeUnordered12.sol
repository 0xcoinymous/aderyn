// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_RefundSafeUnordered12 {
    mapping(bytes32 => uint256) public executed; mapping(address=>mapping(bytes32=>bool)) public used;

    function _consume(address signer,bytes32 id) internal { require(!used[signer][id],"used"); used[signer][id]=true; }

    function refundBySig(address signer,address recipient,uint256 amount,bytes32 actionId,bytes32 authorizationId,uint8 v,bytes32 r,bytes32 s) external {
        bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,authorizationId));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        _consume(signer,authorizationId); executed[actionId] += amount;
    }
}
