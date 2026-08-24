// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_TreasurySafeAuthorizationId06 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public treasuryPaid;
    mapping(bytes32 => bool) public usedAuthorization;

    constructor(address signer_) { authorizedSigner = signer_; }

    function payInvoice(address recipient, uint256 amount, bytes32 invoice, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedAuthorization[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(recipient, amount, invoice, authorizationId));

        require(SR_ReplayBenchSignatureChecker.isValidSignatureNow(authorizedSigner, digest, signature), "invalid signature");

        usedAuthorization[authorizationId] = true;

        treasuryPaid[recipient] += amount;
    }
}
