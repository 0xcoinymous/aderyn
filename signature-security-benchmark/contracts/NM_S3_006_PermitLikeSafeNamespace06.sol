// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_PermitLikeSafeNamespace06 {
    uint256 public totalProcessed;
    mapping(address => uint256) public signerNonces;
    mapping(address => uint256) public cosignerNonces;

    function permit(address signer, address cosigner, address recipient, uint256 amount, bytes32 actionId, uint256 signerNonce, uint256 cosignerNonce, uint8 signerV, bytes32 signerR, bytes32 signerS, uint8 cosignerV, bytes32 cosignerR, bytes32 cosignerS) external {
        require(signerNonce == signerNonces[signer], "wrong signer nonce");
        require(cosignerNonce == cosignerNonces[cosigner], "wrong cosigner nonce");
        bytes32 digest = keccak256(abi.encode(signer, cosigner, recipient, amount, actionId, signerNonce, cosignerNonce));
        require(NM_NonceBenchLib.recoverChecked(digest, signerV, signerR, signerS) == signer, "invalid signer signature");
        require(NM_NonceBenchLib.recoverChecked(digest, cosignerV, cosignerR, cosignerS) == cosigner, "invalid cosigner signature");
        signerNonces[signer] = signerNonce + 1;
        cosignerNonces[cosigner] = cosignerNonce + 1;
        totalProcessed += amount;
    }
}
