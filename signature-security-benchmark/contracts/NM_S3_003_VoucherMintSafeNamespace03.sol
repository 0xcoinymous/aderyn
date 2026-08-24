// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_VoucherMintSafeNamespace03 {
    
    mapping(address => uint256) public processedFor;
    mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => mapping(bytes32 => bool)) public canceled;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }
    function cancel(bytes32 authorizationId) external { canceled[msg.sender][authorizationId] = true; }

    function mintVoucher(address signer, address recipient, uint256 amount, bytes32 actionId, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external  {
        require(!authorizationState[signer][authorizationId], "used"); require(!canceled[signer][authorizationId], "canceled");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, authorizationId));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        authorizationState[signer][authorizationId] = true;
        processedFor[recipient] += amount;
    }
}
