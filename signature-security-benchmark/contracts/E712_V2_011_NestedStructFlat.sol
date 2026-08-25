// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./E712_BenchLib.sol";

contract E712_NestedStructFlat {
    mapping(bytes32 => bool) public usedAuthorization;
    address public lastRecipient;
    address public lastToken;
    address public lastTarget;
    uint256 public lastAmount;
    bytes32 public lastDataHash;
    struct Asset { address token; uint256 amount; }
    bytes32 private constant ASSET_TYPEHASH=keccak256("Asset(address token,uint256 amount)");
    bytes32 private constant TYPEHASH = keccak256("Action(address signer,Asset asset,bytes32 actionId,bytes32 authId)Asset(address token,uint256 amount)");
    function execute(address signer, address recipient, address token, address target, uint256 amount, bytes32 actionId, bytes32 authId, bytes calldata callData, uint8 v, bytes32 r, bytes32 s, Asset calldata asset) external {
        bytes32 structHash=keccak256(abi.encode(TYPEHASH,signer,asset.token,asset.amount,actionId,authId));
        bytes32 digest=E712_BenchLib.typedDataHash(E712_BenchLib.domain("E712 Structured","1",address(this)),structHash);
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
