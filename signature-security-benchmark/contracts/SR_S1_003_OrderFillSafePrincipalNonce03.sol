// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_OrderFillSafePrincipalNonce03 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public filledAmount;
    mapping(address => uint256) public nonces;

    constructor(address signer_) { authorizedSigner = signer_; }

    function fillOrder(bytes32 orderId, address maker, address taker, uint256 amount, uint256 nonce, bytes calldata signature) external {
        require(nonce == nonces[maker], "wrong nonce");

        bytes32 digest = keccak256(abi.encode(orderId, maker, taker, amount, nonce));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        nonces[maker] = nonce + 1;

        filledAmount[orderId] += amount;
    }
}
