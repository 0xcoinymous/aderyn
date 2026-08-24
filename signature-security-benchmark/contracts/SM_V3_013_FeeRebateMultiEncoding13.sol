// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";
contract SM_FeeRebateMultiEncoding13 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedEncoding;
    mapping(bytes32 => bool) public completed;
    uint256 public completionCount;
    mapping(address => bytes32) public actorLastAction;
    constructor(address signer_) { authorizedSigner = signer_; }
    function rebateBySigFull(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(signature.length == 65, "length"); bytes32 key = keccak256(signature); require(!usedEncoding[key], "used");
        (bytes32 r, bytes32 s, uint8 v)=SM_MalleabilityBenchLib.split65(signature); require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid");
        usedEncoding[key]=true; completed[actionId] = true;
        completionCount += 1;
    }
    function rebateBySigCompact(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(signature.length == 64, "length"); bytes32 key = keccak256(signature); require(!usedEncoding[key], "used");
        require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid");
        usedEncoding[key]=true; completed[actionId] = true;
        completionCount += 1;
        actorLastAction[actor] = actionId;
                if (recipient == actor) actorLastAction[actor] = bytes32(0);
    }
}
