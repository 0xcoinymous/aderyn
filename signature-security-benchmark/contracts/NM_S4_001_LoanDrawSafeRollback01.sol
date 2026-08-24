// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_LoanDrawSafeRollback01 {
    
    mapping(address => uint256) public credits;
    mapping(address => uint256) public nonces; mapping(bytes32 => bool) public failed;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function drawBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, address target, bytes calldata payload, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        nonces[signer] = nonce + 1;
        (bool ok,) = target.call(payload);
        failed[actionId] = !ok;
        credits[recipient] += amount;
    }
}
