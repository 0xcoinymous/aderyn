// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AirdropAdversarialSafe03 {
    
    mapping(address => uint256) public nonces;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function claimBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        require(signer == msg.sender, "caller must sign"); require(nonce == nonces[msg.sender], "wrong nonce"); bytes32 digest = keccak256(abi.encode(msg.sender, recipient, amount, actionId, nonce));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        nonces[msg.sender] = nonce + 1;
    }
}
