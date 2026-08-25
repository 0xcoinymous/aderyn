// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./E712_BenchLib.sol";

contract E712_StructArray {
    mapping(bytes32 => bool) public usedAuthorization;
    address public lastRecipient;
    address public lastToken;
    address public lastTarget;
    uint256 public lastAmount;
    bytes32 public lastDataHash;
    struct Asset { address token; uint256 amount; }
    bytes32 private constant TYPEHASH=keccak256("Action(address signer,Asset[] assets,bytes32 authId)Asset(address token,uint256 amount)"); bytes32 private constant ASSET_TYPEHASH=keccak256("Asset(address token,uint256 amount)");
    function _hashAssets(Asset[] calldata assets) internal pure returns(bytes32){bytes32[] memory h=new bytes32[](assets.length); for(uint256 i=0;i<assets.length;i++){h[i]=keccak256(abi.encode(ASSET_TYPEHASH,assets[i].token,assets[i].amount));} return keccak256(abi.encodePacked(h));}
    function execute(address signer, address recipient, address token, address target, uint256 amount, bytes32 actionId, bytes32 authId, bytes calldata callData, uint8 v, bytes32 r, bytes32 s, Asset[] calldata assets) external {
        bytes32 structHash=keccak256(abi.encode(TYPEHASH,signer,_hashAssets(assets),authId));
        bytes32 digest=E712_BenchLib.typedDataHash(E712_BenchLib.domain("E712 Struct Safe","1",address(this)),structHash);
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
