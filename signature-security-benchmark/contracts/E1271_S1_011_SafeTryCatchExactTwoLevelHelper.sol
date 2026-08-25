// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeTryCatchExactTwoLevelHelper011 {
    address public immutable authorizedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { authorizedSigner = signer_; }

    function _leaf(address signer, bytes32 hash, bytes calldata signature) private view returns (bool) {
        try E1271_IERC1271(signer).isValidSignature(hash, signature) returns (bytes4 value) {
            return value == 0x1626ba7e;
        } catch {
            return false;
        }
    }

    function _authorize(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        bool ok = _leaf(signer, hash, signature);
        return ok;
    }

    function execute(bytes32 hash, bytes calldata signature) external returns (bool) {
        if (_authorize(authorizedSigner, hash, signature)) {
            unchecked { accepted++; }
            lastHash = keccak256(abi.encode(lastHash, hash));
            return true;
        }
        return false;
    }
}
