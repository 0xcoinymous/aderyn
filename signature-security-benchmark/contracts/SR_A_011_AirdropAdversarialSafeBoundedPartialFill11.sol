// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AirdropAdversarialSafeBoundedPartialFill11 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public filled;

    constructor(address signer_) { authorizedSigner = signer_; }

    function fill(bytes32 orderId, address maker, uint256 maxAmount, uint256 fillAmount, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(orderId, maker, maxAmount));
        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");
        uint256 next = filled[orderId] + fillAmount;
        require(next <= maxAmount, "overfill");
        filled[orderId] = next;
    }
}
