// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_BridgeReleaseNonceNamespace04 {
    mapping(bytes32 => bool) public completed;
    mapping(address => uint256) public nonces;

    function releaseBySig(address signer, address cosigner, address recipient, uint256 amount, bytes32 actionId, uint256 nonce, uint8 signerV, bytes32 signerR, bytes32 signerS, uint8 cosignerV, bytes32 cosignerR, bytes32 cosignerS) external {
        require(nonce == nonces[signer], "wrong signer nonce");
        bytes32 digest = keccak256(abi.encode(signer, cosigner, recipient, amount, actionId, nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, signerV, signerR, signerS) == signer, "invalid signer signature");
        require(NM_NonceBenchLib.recoverChecked(digest, cosignerV, cosignerR, cosignerS) == cosigner, "invalid cosigner signature");
        nonces[signer] = nonce + 1;
        completed[actionId] = true;
    }
}
