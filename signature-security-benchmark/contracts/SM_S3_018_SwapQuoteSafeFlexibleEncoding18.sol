// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_SwapQuoteSafeFlexibleEncoding18 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(address => mapping(address => uint256)) public allowance;

    mapping(bytes32 => uint256) public stage;
    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        (bytes32 r,bytes32 s,uint8 v)=SM_MalleabilityBenchLib.splitFlexible(signature); require(!usedAuthorization[actionId],"used"); require(SM_MalleabilityBenchLib.recoverCanonical(digest,v,r,s)==authorizedSigner,"invalid"); usedAuthorization[actionId]=true;
        allowance[actor][recipient] = amount;
        stage[actionId] = stage[actionId] == 0 ? 1 : stage[actionId] + 1;
    }
}
