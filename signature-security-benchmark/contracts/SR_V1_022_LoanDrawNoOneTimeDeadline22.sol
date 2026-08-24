// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LoanDrawNoOneTimeDeadline22 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public facilityDrawn;

    constructor(address signer_) { authorizedSigner = signer_; }

    function drawLoan(address borrower, uint256 amount, bytes32 facilityId, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(borrower, amount, facilityId, deadline));

        require(_verifySignature(digest, signature), "invalid signature");

        facilityDrawn[facilityId] += amount;
    }


    function _verifySignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
