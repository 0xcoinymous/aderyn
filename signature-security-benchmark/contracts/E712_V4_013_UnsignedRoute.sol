// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./E712_BenchLib.sol";

contract E712_UnsignedRoute {
    mapping(bytes32 => bool) public usedAuthorization;
    address public lastRecipient;
    address public lastToken;
    address public lastTarget;
    uint256 public lastAmount;
    bytes32 public lastDataHash;
    bytes32 private constant TYPEHASH=keccak256("Action(address signer,bytes32 actionId,bytes32 authId,bytes32 dataHash)");
    function execute(address signer, address recipient, address token, address target, uint256 amount, bytes32 actionId, bytes32 authId, bytes calldata callData, uint8 v, bytes32 r, bytes32 s, bytes32 routeHash) external {
        bytes32 structHash=keccak256(abi.encode(TYPEHASH,signer,actionId,authId,keccak256(callData)));
        bytes32 digest=E712_BenchLib.typedDataHash(E712_BenchLib.domain("E712 Runtime","1",address(this)),structHash);
        require(E712_BenchLib.recoverChecked(digest,v,r,s)==signer,"invalid signature");
        require(!usedAuthorization[authId], "used");
        usedAuthorization[authId] = true;
        lastRecipient = recipient;
        lastToken = token;
        lastTarget = target;
        lastAmount = amount;
        lastDataHash = keccak256(callData);
        lastDataHash=routeHash;
    }
}
