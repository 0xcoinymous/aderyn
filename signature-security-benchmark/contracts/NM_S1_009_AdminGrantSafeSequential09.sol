// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AdminGrantSafeSequential09 {
    mapping(address => uint256) public credits; mapping(address=>uint256) public nonces;

    function _expected(address signer) internal view returns(uint256){ return nonces[signer]; } function _consume(address signer,uint256 nonce) internal { nonces[signer]=nonce+1; }

    function grantBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==_expected(signer),"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        _consume(signer,nonce); credits[recipient] += amount;
    }
}
