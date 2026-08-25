// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_CallerHardcodesHashBranchWrapper036 {
    address public immutable authorizedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { authorizedSigner = signer_; }

    function validate(address signer, bytes32 hash, bytes calldata signature) public view returns (bool) {
        bytes32 fixedHash = keccak256("E1271_CALLER_FIXED");
        bytes4 result = E1271_IERC1271(signer).isValidSignature(fixedHash, signature);
        hash;
        return result == 0x1626ba7e;
    }

    function execute(bytes32 hash, bytes calldata signature) external returns (bool) {
        bool ok = validate(authorizedSigner, hash, signature);
        require(ok, "invalid");
        accepted = accepted == 0 ? 1 : accepted + 2;
        lastHash = bytes32(uint256(hash) ^ accepted);
        return true;
    }
}
