// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_VoucherMintSafeSequential03 {
    
    mapping(address => uint256) public processedFor;
    mapping(address => uint256) public nonces;

    

    function _isValid(bytes32 digest, address expectedSigner, uint8 v, bytes32 r, bytes32 s) internal pure returns (bool) {
        return NM_NonceBenchLib.recover(digest, v, r, s) == expectedSigner;
    }

    function mintVoucher(address signer, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external  {
        require(nonce == nonces[signer], "wrong nonce");
        require(block.timestamp <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(signer, recipient, amount, actionId, nonce, deadline, address(this), block.chainid));
        require(_isValid(digest, signer, v, r, s), "invalid signature");
        nonces[signer] = nonce + 1;
        processedFor[recipient] += amount;
    }
}
