// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_SelfAuthorizingRegistryOneLevelHelper027 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    mapping(address => bool) public authorized;
    function enroll() external { authorized[msg.sender] = true; }

    function _core(bytes32 hash, bytes calldata signature) internal view returns (bytes4) {
        address recovered = E1271_BenchECDSA.recover(hash, signature);
        return authorized[recovered] ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return _core(hash, signature);
    }
}
