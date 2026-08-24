// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_SessionSpendSafeRawCanonical14 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    constructor(address signer_) { authorizedSigner = signer_; }

    function spendBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId));
        bytes32 digest = keccak256(abi.encode(bytes32(uint256(0x1901)), address(this), inner));
        if (uint256(s)==0 || uint256(s)>0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert("s"); if (v!=27 && v!=28) revert("v"); address recovered=ecrecover(digest,v,r,s); require(recovered!=address(0) && recovered==authorizedSigner,"invalid");
        cumulative[actionId] += amount;
        participant[actor] = true;
    }
}
