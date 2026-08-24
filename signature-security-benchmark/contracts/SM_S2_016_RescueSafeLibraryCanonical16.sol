// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RescueSafeLibraryCanonical16 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;

    constructor(address signer_) { authorizedSigner = signer_; }

    function rescueBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        bool valid=SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner; require(valid,"invalid");
        executedAt[actionId] = block.number;
        calls += 1;
    }
}
