// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_VaultHarvestAdversarialSafe11 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    bytes32 public lastContext;
    constructor(address signer_) { authorizedSigner = signer_; }

    function harvestBySig(address actor,address recipient,uint256 amount,bytes32 actionId,uint8 v,bytes32 r,bytes32 s) external {
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        uint256 upper=0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0; require(uint256(s)<=upper && uint256(s)>0,"s"); require(v==27||v==28,"v"); require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        spent[actor] += amount;
        aggregate += amount;
        lastContext = keccak256(abi.encode(actor, actionId));
    }
}
