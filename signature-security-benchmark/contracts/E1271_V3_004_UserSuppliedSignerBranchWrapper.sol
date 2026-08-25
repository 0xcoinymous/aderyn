// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_UserSuppliedSignerBranchWrapper004 {
    uint256 public accepted;
    bytes32 public lastHash;

    function validate(address signer, bytes32 hash, bytes calldata signature) public view returns (bool) {
        bytes4 result = E1271_IERC1271(signer).isValidSignature(hash, signature);
        return result == 0x1626ba7e;
    }

    function execute(address signer, bytes32 hash, bytes calldata signature) external returns (bool) {
        bool ok = validate(signer, hash, signature);
        require(ok, "invalid");
        accepted = accepted == 0 ? 1 : accepted + 2;
        lastHash = bytes32(uint256(hash) ^ accepted);
        return true;
    }
}
