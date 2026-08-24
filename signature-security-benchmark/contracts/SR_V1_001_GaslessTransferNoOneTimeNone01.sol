// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_GaslessTransferNoOneTimeNone01 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public transferred;

    constructor(address signer_) { authorizedSigner = signer_; }

    function transferBySig(address from, address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(from, to, amount));

        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");

        transferred[to] += amount;
    }
}
