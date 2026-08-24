// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_StakingExitNonceNamespace15 {
    struct MarketNonceState { uint256 current; }
    mapping(address => uint256) public processed;
    mapping(address => mapping(bytes32 => MarketNonceState)) public orderNonce;

    function exitBySig(address signer,address recipient,address token,address wallet,bytes32 lane,bytes32 market,uint256 sourceChain,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce == orderNonce[signer][market].current, "wrong market nonce");
        bytes32 digest = keccak256(abi.encode(signer, market, recipient, amount, nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        orderNonce[signer][bytes32(0)].current = nonce + 1;
        processed[recipient] += amount;
    }
}
