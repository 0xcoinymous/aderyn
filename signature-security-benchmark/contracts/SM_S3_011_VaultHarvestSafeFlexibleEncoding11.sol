// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_VaultHarvestSafeFlexibleEncoding11 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function harvestBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actionId != bytes32(0), "zero action");
        uint256 nonce=nonces[actor];
        bytes32 digest=keccak256(abi.encode(actor,recipient,amount,actionId,nonce,address(this)));
        require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); nonces[actor]=nonce+1;
        spent[actor] += amount;
        aggregate += amount;
    }
}
