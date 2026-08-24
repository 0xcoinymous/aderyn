// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_FeeRebateSafeRawCanonical13 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;

    constructor(address signer_) { authorizedSigner = signer_; }

    function rebateBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        require(uint256(s)>0 && uint256(s)<=0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0,"high s"); require(v==27||v==28,"v"); require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
    }
}
