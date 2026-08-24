// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./NM_NonceBenchLib.sol";

contract NM_AirdropNonceNamespace10 {
    uint256 public successful; bytes32 public lastAction; mapping(address=>mapping(address=>uint256)) public walletNonces;

    

    function claimBySig(address signer,address recipient,address token,address wallet,bytes32 lane,bytes32 market,uint256 sourceChain,uint256 amount,bytes32 actionId,uint256 nonce,uint8 v,bytes32 r,bytes32 s) external {
        require(nonce==walletNonces[wallet][signer],"wrong nonce"); bytes32 digest=keccak256(abi.encode(wallet,signer,recipient,amount,nonce));
        require(NM_NonceBenchLib.recoverChecked(digest, v, r, s) == signer, "invalid signature");
        walletNonces[wallet][msg.sender]=nonce+1; successful += 1; lastAction = actionId;
    }
}
