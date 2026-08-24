// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SignatureReplayInterproceduralSafe {
    address public signer;
    mapping(bytes32 => bool) public used;
    uint256 public executions;

    constructor(address signer_) { signer = signer_; }

    function execute(bytes32 authorizationId, uint8 v, bytes32 r, bytes32 s) external {
        require(!_isUsed(authorizationId), "used");
        bytes32 digest = keccak256(abi.encode(authorizationId));
        require(_valid(digest, v, r, s), "bad sig");
        _consume(authorizationId);
        executions++;
    }

    function _isUsed(bytes32 id) internal view returns (bool) { return used[id]; }
    function _consume(bytes32 id) internal { used[id] = true; }
    function _valid(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal view returns (bool) {
        return ecrecover(digest, v, r, s) == signer;
    }
}
