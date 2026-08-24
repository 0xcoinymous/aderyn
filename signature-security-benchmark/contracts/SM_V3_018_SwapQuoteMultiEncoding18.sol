// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_SwapQuoteMultiEncoding18 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedEncoding;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    bytes32 public lastAction;
    constructor(address signer_) { authorizedSigner = signer_; }

    function swapBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        require(signature.length == 65 || signature.length == 66, "length");
        uint256 offset = signature.length == 66 ? 1 : 0;
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := calldataload(add(signature.offset, offset)) s := calldataload(add(add(signature.offset, offset), 32)) v := byte(0, calldataload(add(add(signature.offset, offset), 64))) }
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 && (v == 27 || v == 28), "canonical");
        bytes32 encodingKey = keccak256(signature); require(!usedEncoding[encodingKey], "used");
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid"); usedEncoding[encodingKey] = true;
        cumulative[actionId] += amount;
        participant[actor] = true;
        lastAction = actionId;
    }
}
