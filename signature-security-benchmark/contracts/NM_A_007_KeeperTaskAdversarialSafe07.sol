// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_KeeperTaskAdversarialSafe07 {
    
    mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(bytes32 => bool)) public canceled;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }
    function cancel(bytes32 id) external { canceled[msg.sender][id] = true; }

    function executeTask(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        require(!authorizationState[signer][id] && !canceled[signer][id], "invalid"); bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, id));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        authorizationState[signer][id] = true;
    }
}
