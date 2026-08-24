// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_AffiliateSafeDomainVersion11 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public affiliateCredit;
    mapping(bytes32 => bool) public used; uint256 public constant PROTOCOL_VERSION = 3;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function creditAffiliate(address affiliate, uint256 amount, bytes32 campaign, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(affiliate, amount, campaign, PROTOCOL_VERSION, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        used[authorizationId] = true;

        affiliateCredit[affiliate] += amount;
    }
}
