// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_GovernanceVoteSafeRawCanonical07 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public credited;

    constructor(address signer_) { authorizedSigner = signer_; }

    function _canonicalRecover(bytes32 d,uint8 vv,bytes32 rr,bytes32 ss) internal pure returns(address) { require(uint256(ss)>0 && uint256(ss)<=0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0,"s"); require(vv==27||vv==28,"v"); address a=ecrecover(d,vv,rr,ss); require(a!=address(0),"zero"); return a; }

    function voteBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(_canonicalRecover(digest,v,r,s)==authorizedSigner,"invalid");
        credited[recipient] += amount;
    }
}
