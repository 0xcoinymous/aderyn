// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_UserSuppliedSignerPublicValidationWrapper005 {
    uint256 public accepted;
    bytes32 public lastHash;

    function _raw(address signer, bytes32 hash, bytes calldata signature) internal view returns (bool) {
        bytes4 result = E1271_IERC1271(signer).isValidSignature(hash, signature);
        return result == 0x1626ba7e;
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
