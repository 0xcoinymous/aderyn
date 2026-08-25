// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./E712_BenchLib.sol";

contract E712_NestedHashFinal {
    mapping(bytes32 => bool) public usedAuthorization;
    address public lastRecipient;
    address public lastToken;
    address public lastTarget;
    uint256 public lastAmount;
    bytes32 public lastDataHash;
    bytes32 private constant TYPEHASH=keccak256("Action(address signer,address recipient,address token,address target,uint256 amount,bytes32 dataHash,bytes32 actionId,bytes32 authId)");
    struct Asset {address token;uint256 amount;} bytes32 private constant ASSET_TYPEHASH=keccak256("Asset(address token,uint256 amount)");
    function execute(address signer, address recipient, address token, address target, uint256 amount, bytes32 actionId, bytes32 authId, bytes calldata callData, uint8 v, bytes32 r, bytes32 s, Asset calldata asset) external {
        bytes32 structHash=keccak256(abi.encode(keccak256("Nested(address signer,Asset asset,bytes32 authId)Asset(address token,uint256 amount)"),signer,keccak256(abi.encode(ASSET_TYPEHASH,asset.token,asset.amount)),authId));
        bytes32 domainSeparator=E712_BenchLib.domain("E712 Final Safe","1",address(this));
        bytes32 digest=E712_BenchLib.typedDataHash(domainSeparator,structHash);
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
