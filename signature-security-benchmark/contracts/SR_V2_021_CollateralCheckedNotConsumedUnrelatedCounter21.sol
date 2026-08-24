// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_CollateralCheckedNotConsumedUnrelatedCounter21 {
    address public immutable authorizedSigner; SR_IReplayBenchVerifier public immutable verifier;
    mapping(address => uint256) public collateralOut;
    mapping(bytes32 => bool) public used; uint256 public executionCounter;

    constructor(address signer_, SR_IReplayBenchVerifier verifier_) { authorizedSigner = signer_; verifier = verifier_; }

    function withdrawCollateral(address account, address asset, uint256 amount, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(account, asset, amount, authorizationId));

        require(verifier.isValid(authorizedSigner, digest, signature), "invalid signature");

        executionCounter += 1;

        collateralOut[account] += amount;
    }
}
