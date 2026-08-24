// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_LoanDrawSafeUnordered01 {
    
    mapping(address => uint256) public credits;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    

    

    function drawBySig(address signer, address recipient, uint256 amount, bytes32 actionId, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external  {
        require(!authorizationState[signer][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, authorizationId, address(this), block.chainid));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        authorizationState[signer][authorizationId] = true;
        credits[recipient] += amount;
    }
}
