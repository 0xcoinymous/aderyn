// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_RefundAdversarialSafe09 {
    
    mapping(bytes32 => bool) public usedDigest; uint256 public counter;

    

    

    function refundBySig(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, bytes32 id, bytes32 lane, uint8 v, bytes32 r, bytes32 s) external  {
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce)); require(!usedDigest[digest], "used");
        require(ecrecover(digest, v, r, s) == signer, "invalid signature");
        usedDigest[digest] = true; counter += 1;
    }
}
