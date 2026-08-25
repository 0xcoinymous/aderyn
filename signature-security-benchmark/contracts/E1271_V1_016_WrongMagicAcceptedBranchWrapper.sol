// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_WrongMagicAcceptedBranchWrapper016 {
    address public immutable authorizedSigner;
    uint256 public accepted;
    bytes32 public lastHash;

    constructor(address signer_) { authorizedSigner = signer_; }

    function validate(address signer, bytes32 hash, bytes calldata signature) public view returns (bool) {
        (bool success, bytes memory ret) = signer.staticcall(abi.encodeWithSelector(E1271_IERC1271.isValidSignature.selector, hash, signature));
        if (!success || ret.length < 32) return false;
        bytes32 word = abi.decode(ret, (bytes32));
        return bytes4(word) == 0x20c13b0b;
    }

    function execute(bytes32 hash, bytes calldata signature) external returns (bool) {
        bool ok = validate(authorizedSigner, hash, signature);
        require(ok, "invalid");
        accepted = accepted == 0 ? 1 : accepted + 2;
        lastHash = bytes32(uint256(hash) ^ accepted);
        return true;
    }
}
