// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SM_MalleabilityBenchLib.sol";

contract SM_OracleUpdateHighSAccept08 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public credited;

    constructor(address signer_) { authorizedSigner = signer_; }

    function updateBySig(address actor, address recipient, uint256 amount, bytes32 actionId, uint8 v, bytes32 r, bytes32 s) external {
        require(amount != 0, "zero amount");
        bytes32 digest = keccak256(abi.encode(actor, recipient, amount, actionId, address(this)));
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != authorizedSigner) revert("invalid signature");
        credited[recipient] += amount;
    }
}
