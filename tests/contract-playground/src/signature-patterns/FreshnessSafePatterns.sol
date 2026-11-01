// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Signed authorizations that are fresh or one-time; none may be reported.

// DAI-style permit: a zero expiry is the signer's explicit choice of no expiry; the nonce is consumed.
contract OptOutExpiryPermit {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;
    function permit(address holder, address spender, uint256 nonce, uint256 expiry, bool allowed, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, holder, spender, nonce, expiry, allowed));
        require(holder == ecrecover(digest, v, r, s), "invalid-permit");
        require(expiry == 0 || block.timestamp <= expiry, "permit-expired");
        require(nonce == nonces[holder]++, "invalid-nonce");
        allowance[holder][spender] = allowed ? type(uint256).max : 0;
    }
}

// A require wrapper library and a time helper.
library Require {
    function that(bool must, bytes32 reason) internal pure {
        if (!must) {
            revert(string(abi.encodePacked(reason)));
        }
    }
}

contract WrappedDeadlinePermit {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;
    function _now() internal view returns (uint256) {
        return block.timestamp;
    }
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        Require.that(_now() <= deadline, "expired");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, owner, spender, value, nonces[owner]++, deadline));
        Require.that(owner == ecrecover(digest, v, r, s), "signature");
        allowance[owner][spender] = value;
    }
}

// A bridge withdrawal identified by a signed transaction id that is marked done.
contract OneTimeTransactionId {
    address public validator;
    mapping(bytes32 => bool) public txList;
    mapping(address => uint256) public balances;
    function withdraw(bytes32 txID, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        require(!txList[txID], "done");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, txID, msg.sender, amount));
        require(ecrecover(digest, v, r, s) == validator, "signature");
        txList[txID] = true;
        balances[msg.sender] += amount;
    }
}

// A signed cancellation only marks the order cancelled.
contract SignedCancellation {
    mapping(bytes32 => bool) public cancelled;
    function cancelOrder(bytes32 orderHash, address maker, uint8 v, bytes32 r, bytes32 s) external {
        require(ecrecover(keccak256(abi.encode(address(this), block.chainid, "cancel", orderHash)), v, r, s) == maker, "maker");
        cancelled[orderHash] = true;
    }
}
