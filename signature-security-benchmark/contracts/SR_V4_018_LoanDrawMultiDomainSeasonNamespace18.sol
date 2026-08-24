// SPDX-License-Identifier: MIT
pragma solidity 0.8.29;
import "./SR_ReplayBenchLib.sol";

contract SR_LoanDrawMultiDomainSeasonNamespace18 {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e; address public immutable wallet;
    mapping(bytes32 => uint256) public facilityDrawn;
    mapping(uint256 => mapping(bytes32 => bool)) public usedByDomain;

    constructor(address wallet_) { wallet = wallet_; }

    function execute(address borrower, uint256 amount, bytes32 facilityId, uint256 seasonId, bytes32 authorizationId, bytes calldata signature) external {
        require(!usedByDomain[seasonId][authorizationId], "used");
        bytes32 digest = keccak256(abi.encode(borrower, amount, facilityId, authorizationId));
        require(SR_IReplayBench1271(wallet).isValidSignature(digest, signature) == MAGICVALUE, "invalid signature");
        usedByDomain[seasonId][authorizationId] = true;
        facilityDrawn[facilityId] += amount;
    }
}
