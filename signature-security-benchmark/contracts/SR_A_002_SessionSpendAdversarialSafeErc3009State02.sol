// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_SessionSpendAdversarialSafeErc3009State02 {
    address public immutable authorizedSigner;
    mapping(address => mapping(bytes32 => bool)) public authorizationState; mapping(address => uint256) public transferred;

    constructor(address signer_) { authorizedSigner = signer_; }

    function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes calldata signature) external {
        require(block.timestamp > validAfter && block.timestamp < validBefore, "outside window");
        require(!authorizationState[from][nonce], "used");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, from, to, value, validAfter, validBefore, nonce));
        _authorize(digest, signature);
        authorizationState[from][nonce] = true;
        transferred[to] += value;
    }


    function _authorize(bytes32 digest, bytes calldata signature) internal view {
        require(_recoverMatches(digest, signature), "invalid signature");
    }

    function _recoverMatches(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        return SR_ReplayBenchECDSA.recover(digest, signature) == authorizedSigner;
    }
}
