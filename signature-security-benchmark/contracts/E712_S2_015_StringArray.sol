// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./E712_BenchLib.sol";

contract E712_StringArray {
    mapping(bytes32 => bool) public usedAuthorization;
    address public lastRecipient;
    address public lastToken;
    address public lastTarget;
    uint256 public lastAmount;
    bytes32 public lastDataHash;
    bytes32 private constant TYPEHASH=keccak256("Action(address signer,string[] labels,bytes32 authId)");
    function _hashStrings(string[] calldata labels) internal pure returns(bytes32){bytes32[] memory h=new bytes32[](labels.length); for(uint256 i=0;i<labels.length;i++){h[i]=keccak256(bytes(labels[i]));} return keccak256(abi.encodePacked(h));}
    function execute(address signer, address recipient, address token, address target, uint256 amount, bytes32 actionId, bytes32 authId, bytes calldata callData, uint8 v, bytes32 r, bytes32 s, string[] calldata labels) external {
        bytes32 structHash=keccak256(abi.encode(TYPEHASH,signer,_hashStrings(labels),authId));
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
