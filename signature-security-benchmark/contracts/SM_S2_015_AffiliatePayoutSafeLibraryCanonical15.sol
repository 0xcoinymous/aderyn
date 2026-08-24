// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_AffiliatePayoutSafeLibraryCanonical15 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function payAffiliate(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        address recovered=SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s); if(recovered!=authorizedSigner) revert("invalid");
        spent[actor] += amount;
        aggregate += amount;
    }
}
