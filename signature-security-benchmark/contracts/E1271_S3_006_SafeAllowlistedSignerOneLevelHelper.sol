// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeAllowlistedSignerOneLevelHelper006 {
    address public immutable admin;
    mapping(address => bool) public allowedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { admin = msg.sender; allowedSigner[signer_] = true; }
    function addSigner(address signer_) external { require(msg.sender == admin, "admin"); allowedSigner[signer_] = true; }

    function _inner(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (!allowedSigner[signer]) return false;
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function _check(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        return _inner(signer, hash, signature);
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external returns (bool) {
        bool ok = _check(signer, hash, signature);
        if (!ok) revert("invalid");
        lastHash = hash;
        accepted = accepted + 1;
        return ok;
    }
}
