// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_RefundHighSAccept28 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    mapping(bytes32 => uint256) public stage;
    constructor(address signer_) { authorizedSigner = signer_; }

    function refundBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actionId != bytes32(0), "zero action");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        spent[actor] += amount;
        aggregate += amount;
        stage[actionId] = stage[actionId] == 0 ? 1 : stage[actionId] + 1;
    }
}
