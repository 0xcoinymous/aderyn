// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_WithdrawalAdversarialSafe11 {
    
    mapping(address => uint256) public epoch;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }
    function rotateEpoch() external { epoch[msg.sender] += 1; }

    function withdrawBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == epoch[signer], "wrong epoch"); bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        
    }
}
