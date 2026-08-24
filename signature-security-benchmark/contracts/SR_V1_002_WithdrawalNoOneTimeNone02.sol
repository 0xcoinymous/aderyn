// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_WithdrawalNoOneTimeNone02 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public withdrawn;

    constructor(address signer_) { authorizedSigner = signer_; }

    function withdrawBySig(address user, uint256 amount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(user, amount));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        withdrawn[user] += amount;
    }
}
