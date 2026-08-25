// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./E712_BenchLib.sol";

contract E712_UserChainId {
    mapping(bytes32 => bool) public usedAuthorization;
    address public lastRecipient;
    address public lastToken;
    address public lastTarget;
    uint256 public lastAmount;
    bytes32 public lastDataHash;
    bytes32 private constant TYPEHASH = keccak256("Action(address signer,address recipient,address token,address target,uint256 amount,bytes32 dataHash,bytes32 actionId,bytes32 authId)");
    bytes32 private constant DTYPE = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    function _domain(uint256 suppliedChainId) internal view returns(bytes32) { return keccak256(abi.encode(DTYPE,keccak256(bytes("UserChain")),keccak256(bytes("1")),suppliedChainId,address(this))); }
    function execute(address signer, address recipient, address token, address target, uint256 amount, bytes32 actionId, bytes32 authId, bytes calldata callData, uint8 v, bytes32 r, bytes32 s, uint256 suppliedChainId) external {
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, signer, recipient, token, target, amount, keccak256(callData), actionId, authId));
        bytes32 digest = E712_BenchLib.typedDataHash(_domain(suppliedChainId), structHash);
        require(E712_BenchLib.recoverChecked(digest,v,r,s)==signer,"invalid signature");
        require(!usedAuthorization[authId], "used");
        usedAuthorization[authId] = true;
        lastRecipient = recipient;
        lastToken = token;
        lastTarget = target;
        lastAmount = amount;
        lastDataHash = keccak256(callData);
    }
}
