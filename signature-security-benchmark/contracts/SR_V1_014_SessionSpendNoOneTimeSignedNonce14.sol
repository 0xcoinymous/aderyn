// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SessionSpendNoOneTimeSignedNonce14 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public sessionSpent;

    constructor(address signer_) { authorizedSigner = signer_; }

    function spendSession(address session, address recipient, uint256 amount, uint256 nonce, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(session, recipient, amount, nonce));

        _authorize(digest, signature);

        sessionSpent[session] += amount;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
