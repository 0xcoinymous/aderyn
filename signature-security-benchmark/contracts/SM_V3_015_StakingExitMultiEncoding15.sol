// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_StakingExitMultiEncoding15 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedEncoding;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function exitBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        bytes32 encodingKey = keccak256(signature); require(!usedEncoding[encodingKey], "used");
        bytes memory decoded = abi.decode(signature, (bytes)); require(decoded.length == 65, "inner length"); bytes32 r; bytes32 s; uint8 v; assembly { r := mload(add(decoded,32)) s := mload(add(decoded,64)) v := byte(0,mload(add(decoded,96))) }
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 && (v==27||v==28),"canonical"); require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid"); usedEncoding[encodingKey]=true;
        spent[actor] += amount;
        aggregate += amount;
    }
}
