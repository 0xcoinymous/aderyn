// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RfqNoOneTimeAuthorizationId30 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public rfqFilled;

    constructor(address signer_) { authorizedSigner = signer_; }

    function fillRfq(bytes32 quoteId, address maker, address taker, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(quoteId, maker, taker, amount, authorizationId));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        rfqFilled[quoteId] += amount;
    }
}
