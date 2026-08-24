// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_GovernanceVoteNonceAuthCheck07 {
    
    address public lastRecipient; uint256 public successful;
    mapping(address => uint256) public nonces;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;
    mapping(address => uint256) public sequences;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;
    mapping(address => uint256) public sessionCounters;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function voteBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, bytes32 guardId, uint256 sequence, uint256 sessionSeed, uint8 v, bytes32 r, bytes32 s) external  {
        uint256 word = nonce >> 8; uint256 bit = uint256(1) << uint8(nonce);
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        nonceBitmap[signer][word] |= bit;
        lastRecipient = recipient; successful += 1;
    }
}
