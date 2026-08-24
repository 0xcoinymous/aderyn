// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_RoyaltyCheckedNotConsumedEventOnly32 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public royalties;
    mapping(bytes32 => bool) public used; event AuthorizationConsumed(bytes32 indexed id);

    constructor(address signer_) { authorizedSigner = signer_; }

    function claimRoyalty(address creator, uint256 amount, bytes32 saleId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(creator, amount, saleId, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        emit AuthorizationConsumed(authorizationId);

        royalties[creator] += amount;
    }
}
