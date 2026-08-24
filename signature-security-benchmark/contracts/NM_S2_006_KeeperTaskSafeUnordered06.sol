// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_KeeperTaskSafeUnordered06 {
    
    uint256 public totalProcessed;
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function executeTask(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external  {
        uint256 word = nonce >> 8; uint256 bit = uint256(1) << uint8(nonce);
        require((nonceBitmap[signer][word] & bit) == 0, "used");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce, address(this), block.chainid));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        nonceBitmap[signer][word] |= bit;
        totalProcessed += amount;
    }
}
