// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_UnsafeEOAFallbackPublicValidationWrapper015 {
    uint256 public accepted;
    bytes32 public lastHash;

    function _raw(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        if (signer.code.length == 0) return true;
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        return success && ret.length >= 32 && abi.decode(ret, (bytes4)) == 0x1626ba7e;
    }

    function validate(address signer, bytes32 hash, bytes calldata signature) public view returns (bool) {
        return _raw(signer, hash, signature);
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external returns (bool) {
        require(validate(signer, hash, signature), "invalid");
        lastHash = hash;
        accepted = (accepted << 1) + 1;
        return true;
    }
}
