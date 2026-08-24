// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RoyaltyClaimSafeLibraryCanonical10 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public cumulative;
    mapping(address => bool) public participant;

    constructor(address signer_) { authorizedSigner = signer_; }

    function claimRoyalty(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        (address recovered,bool ok)=SM_MalleabilityBenchLib.tryRecoverCanonical(digest,v,r,s); require(ok && recovered==authorizedSigner,"invalid");
        cumulative[actionId] += amount;
        participant[actor] = true;
    }
}
