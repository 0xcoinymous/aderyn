// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_CrossSmartAccountRawHashOneLevelHelper037 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    constructor(address owner_) { owner = owner_; }

    function _rawApplicationHash(bytes32 hash) internal pure returns (bytes32) { return hash; }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        bytes32 rawHash = _rawApplicationHash(hash);
        address recovered = E1271_BenchECDSA.recover(rawHash, signature);
        return recovered == owner ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _core(hash, signature);
    }
}
