// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_TreasuryPaymentAdversarialSafe06 {
    
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    

    

    function payBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        uint256 word = nonce >> 8; uint256 bit = uint256(1) << uint8(nonce); bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        uint256 flipped = nonceBitmap[signer][word] ^= bit; require((flipped & bit) != 0, "used");
    }
}
