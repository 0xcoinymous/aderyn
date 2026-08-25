// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SafeERC7739SupportDetectionOneLevelHelper006 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    bytes32 private constant SUPPORT_HASH = 0x7739773977397739773977397739773977397739773977397739773977397739;
    constructor(address owner_) { owner = owner_; }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        if (hash == SUPPORT_HASH && signature.length == 0) return 0x77390001;
        bytes32 scoped = keccak256(abi.encode(address(this), block.chainid, hash));
        address recovered = E1271_BenchECDSA.recover(scoped, signature);
        return recovered == owner ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _core(hash, signature);
    }
}
