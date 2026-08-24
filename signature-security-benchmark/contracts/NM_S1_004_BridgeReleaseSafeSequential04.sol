// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BridgeReleaseSafeSequential04 is NM_NonceSignerBase {
    
    mapping(bytes32 => bool) public completed;
    mapping(address => uint256) public nonces;

    

    

    function releaseBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce, deadline, address(this), block.chainid));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        nonces[signer] = nonce + 1;
        completed[actionId] = true;
    }
}
