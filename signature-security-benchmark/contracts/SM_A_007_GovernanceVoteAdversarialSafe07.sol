// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_GovernanceVoteAdversarialSafe07 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public credited;

    constructor(address signer_) { authorizedSigner = signer_; }

    function voteBySig(address actor,address recipient,uint256 amount,bytes32 actionId,uint8 v,bytes32 r,bytes32 s) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(v>=27 && v<=28,"v"); require(uint256(s)!=0 && uint256(s)<=0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0,"s"); address recovered=ecrecover(digest,v,r,s); require(recovered==authorizedSigner && recovered!=address(0),"invalid");
        credited[recipient] += amount;
    }
}
