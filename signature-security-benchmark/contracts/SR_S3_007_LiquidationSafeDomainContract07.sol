// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LiquidationSafeDomainContract07 {
    address public immutable authorizedSigner;
    mapping(bytes32 => uint256) public liquidatedDebt;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function liquidateBySig(address account, uint256 debt, bytes32 positionId, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(account, debt, positionId, address(this), authorizationId));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        used[authorizationId] = true;

        liquidatedDebt[positionId] += debt;
    }
}
