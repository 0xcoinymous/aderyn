// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_BridgeReleaseNoOneTimeNone05 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public bridgeReleased;

    constructor(address signer_) { authorizedSigner = signer_; }

    function releaseBridgeFunds(address recipient, uint256 amount, bytes32 sourceTx, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(recipient, amount, sourceTx));

        _authorize(digest, signature);

        bridgeReleased[recipient] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
