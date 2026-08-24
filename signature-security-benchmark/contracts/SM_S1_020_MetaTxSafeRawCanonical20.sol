// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_MetaTxSafeRawCanonical20 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;

    uint256 public parityCounter;
    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        require(v==27||v==28,"v"); uint256 su=uint256(s); require(su!=0 && su<=0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0,"s"); address recovered=ecrecover(digest,v,r,s); if(recovered!=authorizedSigner) revert("invalid");
        executedAt[actionId] = block.number;
        calls += 1;
        parityCounter += amount & 1;
    }
}
