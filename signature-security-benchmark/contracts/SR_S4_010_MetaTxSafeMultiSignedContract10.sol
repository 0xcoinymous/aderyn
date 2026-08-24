// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_MetaTxSafeMultiSignedContract10 {
    address public immutable authorizedSigner;
    mapping(address => uint256) public metaValue;
    mapping(bytes32 => bool) public used;

    constructor(address signer_) { authorizedSigner = signer_; }

    function executeMeta(address user, address target, uint256 value, bytes32 callHash, bytes32 authorizationId, bytes calldata signature) external {
        require(!used[authorizationId], "used");

        bytes32 digest = keccak256(abi.encode(user, target, value, callHash, address(this), authorizationId));

        (address recovered, bool ok) = SR_ReplayBenchECDSA.tryRecover(digest, signature);
        require(ok && recovered == authorizedSigner, "invalid signature");

        used[authorizationId] = true;

        metaValue[user] += value;
    }
}
