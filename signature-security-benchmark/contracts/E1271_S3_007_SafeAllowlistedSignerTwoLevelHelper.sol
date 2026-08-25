// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeAllowlistedSignerTwoLevelHelper007 {
    address public immutable admin;
    mapping(address => bool) public allowedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { admin = msg.sender; allowedSigner[signer_] = true; }
    function addSigner(address signer_) external { require(msg.sender == admin, "admin"); allowedSigner[signer_] = true; }

    function _leaf(address signer, bytes32 hash, bytes calldata signature) private view returns (bool) {
        if (!allowedSigner[signer]) return false;
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function _authorize(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        bool ok = _leaf(signer, hash, signature);
        return ok;
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external returns (bool) {
        if (_authorize(signer, hash, signature)) {
            unchecked { accepted++; }
            lastHash = keccak256(abi.encode(lastHash, hash));
            return true;
        }
        return false;
    }
}
