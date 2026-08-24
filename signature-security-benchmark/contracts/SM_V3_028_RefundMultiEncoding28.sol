// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RefundMultiEncoding28 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedEncoding;
    mapping(bytes32 => uint256) public totals;

    mapping(bytes32 => uint256) public stage;
    constructor(address signer_) { authorizedSigner = signer_; }

    function refundBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        require(signature.length == 65 || signature.length == 96, "length");
        bytes32 r; bytes32 s; uint8 v;
        if (signature.length == 65) { (r,s,v) = SM_MalleabilityBenchLib.split65(signature); } else { assembly { r := calldataload(signature.offset) s := calldataload(add(signature.offset, 32)) v := byte(31, calldataload(add(signature.offset, 64))) } }
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 && (v == 27 || v == 28), "canonical");
        bytes32 encodingKey = keccak256(signature); require(!usedEncoding[encodingKey], "used"); require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid"); usedEncoding[encodingKey]=true;
        totals[actionId] = totals[actionId] + amount;
        stage[actionId] = stage[actionId] == 0 ? 1 : stage[actionId] + 1;
    }
}
