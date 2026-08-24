// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_PermitLikeMultiDomainCrossFunction21 {
    address public immutable authorizedSigner;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(bytes32 => bool) public usedPrimary;
    mapping(bytes32 => bool) public usedAlternate;

    constructor(address signer_) { authorizedSigner = signer_; }

    function primary(address owner, address spender, uint256 value, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedPrimary[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(owner, spender, value, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        usedPrimary[authorizationId] = true;
        allowance[owner][spender] = value;
    }

    function alternate(address owner, address spender, uint256 value, bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedAlternate[authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(owner, spender, value, authorizationId));
        require(ecrecover(digest, v, r, s) == authorizedSigner, "invalid signature");
        usedAlternate[authorizationId] = true;
        allowance[owner][spender] = value;
    }
}
