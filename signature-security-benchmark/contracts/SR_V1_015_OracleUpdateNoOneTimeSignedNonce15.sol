// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_OracleUpdateNoOneTimeSignedNonce15 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(bytes32 => uint256) public prices; mapping(bytes32 => uint256) public updateCount;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function updatePrice(bytes32 feedId, uint256 price, uint256 reportTime, uint256 nonce, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(feedId, price, reportTime, nonce));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        prices[feedId] = price; updateCount[feedId] += 1;
    }
}
