// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_FeeRebateAdversarialSafe04 {
    address public immutable authority;
    uint256 public globalNonce;
    uint256 public processed;

    constructor(address authority_) { authority = authority_; }

    function rebateBySig(address recipient, uint256 amount, bytes32 actionId, uint256 nonce, uint8 v, bytes32 r, bytes32 s) external {
        require(nonce == globalNonce, "wrong nonce");
        bytes32 digest = keccak256(abi.encode(recipient, amount, actionId, nonce, address(this)));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == authority, "invalid signature");
        globalNonce = nonce + 1;
        processed += amount;
    }
}
