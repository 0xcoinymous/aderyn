// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_PermitLikeCheckedNotConsumedMissingWrite17 {
    address public immutable authorizedSigner;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function permitLike(address owner, address spender, uint256 value, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(owner, spender, value, authorizationId));

        require(SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner, "invalid signature");

        allowance[owner][spender] = value;
    }
}
