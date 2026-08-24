// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_BridgeReleaseHighSAccept04 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public spent;
    uint256 public aggregate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseBySig(address actor, address recipient, uint256 amount, bytes32 actionId, bytes calldata signature) external {
        require(actor != address(0) && recipient != address(0), "zero address");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        (bytes32 r, bytes32 s, uint8 v) = SM_MalleabilityBenchLib.split65(signature);
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        spent[actor] += amount;
        aggregate += amount;
    }
}
