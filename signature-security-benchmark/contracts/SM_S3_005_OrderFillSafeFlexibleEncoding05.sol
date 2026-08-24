// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_OrderFillSafeFlexibleEncoding05 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public usedAuthorization;
    mapping(address => uint256) public balanceDelta;
    mapping(bytes32 => bool) public touched;

    constructor(address signer_) { authorizedSigner = signer_; }

    function fillOrder(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 inner = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));
        require(!usedAuthorization[digest],"used"); require(SM_MalleabilityBenchLib.recoverFlexibleCanonical(digest,signature)==authorizedSigner,"invalid"); usedAuthorization[digest]=true;
        balanceDelta[recipient] += amount;
        touched[actionId] = true;
    }
}
