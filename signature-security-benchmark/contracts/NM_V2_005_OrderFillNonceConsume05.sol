// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_OrderFillNonceConsume05 {
    
    mapping(address => uint256) public recipientAllowance;
    mapping(address => uint256) public nonces; mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(uint256 => uint256)) public nonceBitmap; mapping(address => uint256) public sequences; uint256 public executionCounter; event AuthorizationObserved(address indexed signer, bytes32 indexed id);

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function fillOrder(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 authorizationId, uint256 sequence, bool consumeNonce, uint8 v, bytes32 r, bytes32 s) external  {
        require(!authorizationState[signer][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, authorizationId));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        emit AuthorizationObserved(signer, authorizationId);
        recipientAllowance[recipient] = amount;
    }
}
