// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_SessionSpendAdversarialSafe15 {
    
    mapping(address => mapping(bytes32 => uint256)) public laneNonce;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function spendBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == laneNonce[signer][lane], "wrong lane nonce"); bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, lane, nonce));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        laneNonce[signer][lane] = nonce + 1;
    }
}
