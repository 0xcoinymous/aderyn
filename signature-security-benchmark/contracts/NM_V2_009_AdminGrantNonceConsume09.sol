// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AdminGrantNonceConsume09 {
    mapping(address => uint256) public credits; mapping(address=>uint256) public nonces; mapping(address=>uint256) public lastSeen; mapping(address=>mapping(uint256=>uint256)) public nonceBitmap; mapping(address=>mapping(uint256=>uint256)) public observedBitmap;

    function _next(uint256 current) internal pure returns(uint256){ return current+1; }

    function grantBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,bool directCaller,uint8 v,bytes32 r,bytes32 s) external {
        require(nonces[signer] != type(uint256).max,"disabled"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        _next(nonces[signer]); credits[recipient] += amount;
    }
}
