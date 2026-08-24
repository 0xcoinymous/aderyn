// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_SessionSpendNonceConsume14 {
    uint256 public successful; bytes32 public lastAction; mapping(address=>uint256) public nonces; mapping(address=>uint256) public lastSeen; mapping(address=>mapping(uint256=>uint256)) public nonceBitmap; mapping(address=>mapping(uint256=>uint256)) public observedBitmap;

    function _consume(address signer,uint256 nonce) internal pure returns(uint256){ return nonce+1; }

    function spendBySig(address signer,address recipient,uint256 amount,bytes32 actionId,uint256 nonce,bool directCaller,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==nonces[signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(signer,recipient,amount,actionId,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        uint256 ignored=_consume(signer,nonce); require(ignored>nonce); successful += 1; lastAction = actionId;
    }
}
