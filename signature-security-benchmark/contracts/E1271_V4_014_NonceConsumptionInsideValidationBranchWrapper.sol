// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./E1271_BenchLib.sol";

contract E1271_NonceConsumptionInsideValidationBranchWrapper014 {
    bytes4 internal constant MAGIC = 0x1626ba7e;
    bytes4 internal constant FAIL = 0xffffffff;
    address public immutable owner;
    mapping(address => uint256) public validationNonce;
    constructor(address owner_) { owner = owner_; }

    function validate(bytes32 hash, bytes calldata signature) public returns (bytes4) {
        validationNonce[owner] += 1;
        bytes32 scoped = keccak256(abi.encode(hash, validationNonce[owner]));
        address recovered = E1271_BenchECDSA.recover(scoped, signature);
        return recovered == owner ? MAGIC : FAIL;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external returns (bytes4) {
        return validate(hash, signature);
    }
}
