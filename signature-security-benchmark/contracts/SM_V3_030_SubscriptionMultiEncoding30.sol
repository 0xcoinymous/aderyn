// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_SubscriptionMultiEncoding30 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedEncoding;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public parityCounter;
    constructor(address signer_) { authorizedSigner = signer_; }

    function chargeBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        require(signature.length >= 65, "short"); bytes32 r; bytes32 s; uint8 v; assembly { r := calldataload(signature.offset) s := calldataload(add(signature.offset,32)) v := byte(0,calldataload(add(signature.offset,64))) }
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 && (v==27||v==28), "canonical"); bytes32 encodingKey=keccak256(signature); require(!usedEncoding[encodingKey],"used"); require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid"); usedEncoding[encodingKey]=true;
        allowance[actor][recipient] = amount;
        parityCounter += amount & 1;
    }
}
