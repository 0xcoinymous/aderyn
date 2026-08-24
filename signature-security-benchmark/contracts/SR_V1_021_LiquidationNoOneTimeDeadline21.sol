// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LiquidationNoOneTimeDeadline21 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public liquidatedDebt;

    constructor(address signer_) { authorizedSigner = signer_; }

    function liquidateBySig(address account, uint256 debt, bytes32 positionId, uint256 deadline, bytes calldata signature) external {
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = keccak256(abi.encode(account, debt, positionId, deadline));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        liquidatedDebt[positionId] += debt;
    }
}
