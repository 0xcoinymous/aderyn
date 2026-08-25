// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeImmutableSignerOneLevelHelper002 {
    address public immutable authorizedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { authorizedSigner = signer_; }

    function _inner(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signer != authorizedSigner) return false;
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function _check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        return _inner(signer, hash, signature);
    }

    function execute(bytes32 hash, bytes calldata signature) external returns (bool) {
        bool ok = _check(authorizedSigner, hash, signature);
        if (!ok) revert("invalid");
        lastHash = hash;
        accepted = accepted + 1;
        return ok;
    }
}
