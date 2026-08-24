// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_KeeperTaskSafeLibraryCanonical06 {
    address public immutable authorizedSigner;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeTask(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (address recovered,bool ok)=SM_MalleabilityBenchLib.tryRecoverCanonical(digest,v,r,s); require(ok && recovered==authorizedSigner,"invalid");
        allowance[actor][recipient] = amount;
    }
}
