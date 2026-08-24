// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AffiliatePayoutAdversarialSafe10 {
    
    mapping(address => mapping(bytes32 => bool)) public usedSalt;

    

    

    function payAffiliate(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        require(!usedSalt[signer][id], "used"); bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, id));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        usedSalt[signer][id] = true;
    }
}
