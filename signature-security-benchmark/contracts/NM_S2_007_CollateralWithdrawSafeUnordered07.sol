// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_CollateralWithdrawSafeUnordered07 is NM_NonceSignerBase {
    
    address public lastRecipient; uint256 public successful;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    

    

    function withdrawCollateral(address signer, address recipient, uint256 amount, bytes32 actionId, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external  {
        require(!authorizationState[signer][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, authorizationId, address(this), block.chainid));
        require(_recover(digest, v, r, s) == signer, "invalid signature");
        authorizationState[signer][authorizationId] = true;
        lastRecipient = recipient; successful += 1;
    }
}
