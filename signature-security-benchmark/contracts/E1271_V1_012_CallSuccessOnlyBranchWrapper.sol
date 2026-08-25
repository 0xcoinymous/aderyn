// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_CallSuccessOnlyBranchWrapper012 {
    address public immutable authorizedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { authorizedSigner = signer_; }

    function validate(address signer, bytes32 hash, bytes calldata signature) public view returns (bool) {
        (bool success, ) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        return success;
    }

    function execute(bytes32 hash, bytes calldata signature) external returns (bool) {
        bool ok = validate(authorizedSigner, hash, signature);
        require(ok, "invalid");
        accepted = accepted == 0 ? 1 : accepted + 2;
        lastHash = bytes32(uint256(hash) ^ accepted);
        return true;
    }
}
