// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;

import "./E712_BenchLib.sol";

contract E712_BytesArrayHash {
    mapping(bytes32 => bool) public usedAuthorization;
    address public lastRecipient;
    address public lastToken;
    address public lastTarget;
    uint256 public lastAmount;
    bytes32 public lastDataHash;
    bytes32 private constant TYPEHASH=keccak256("Action(address signer,bytes[] calls,bytes32 authId)");
    function _hashBytesArray(bytes[] calldata calls) internal pure returns(bytes32){bytes32[] memory h=new bytes32[](calls.length); for(uint256 i=0;i<calls.length;i++){h[i]=keccak256(calls[i]);} return keccak256(abi.encodePacked(h));}
    function execute(address signer, address recipient, address token, address target, uint256 amount, bytes32 actionId, bytes32 authId, bytes calldata callData, uint8 v, bytes32 r, bytes32 s, bytes[] calldata calls) external {
        bytes32 structHash=keccak256(abi.encode(TYPEHASH,signer,_hashBytesArray(calls),authId));
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
