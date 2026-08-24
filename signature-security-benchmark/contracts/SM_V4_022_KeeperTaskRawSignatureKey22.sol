// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_KeeperTaskRawSignatureKey22 {
    address public immutable authorizedSigner;
    mapping(bytes32 => bool) public consumedSignature;
    mapping(bytes32 => uint256) public executedAt;
    uint256 public calls;

    uint256 public totalAuthorized;
    constructor(address signer_) { authorizedSigner = signer_; }

    function executeTask(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(amount != 0, "zero amount");
        bytes32 digest = keccak256(abi.encodePacked(actor, recipient, amount, actionId, address(this)));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        bytes32 key = sha256(signature);
        require(!consumedSignature[key], "signature used");
        require(ecrecover(digest,v,r,s)==authorizedSigner,"invalid");
        consumedSignature[key] = true;
        executedAt[actionId] = block.number;
        calls += 1;
        unchecked { totalAuthorized += amount; }
    }
}
