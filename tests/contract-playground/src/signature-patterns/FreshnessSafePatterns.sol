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

// The digest is computed in an unchecked block and verified by a helper; the deadline check follows.
contract UncheckedDigestPermit {
    mapping(address => uint256) public nonces;
    mapping(address => mapping(address => uint256)) public allowance;
    function _isValidSignature(address signer, bytes32 digest, bytes memory signature) internal pure returns (bool) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        return signer == ecrecover(digest, v, r, s);
    }
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external {
        uint256 nonce;
        unchecked { nonce = nonces[owner]++; }
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, owner, spender, value, nonce, deadline));
        require(_isValidSignature(owner, digest, signature), "invalid-permit");
        require(block.timestamp <= deadline, "expired");
        allowance[owner][spender] = value;
    }
}

// An error library's `require_*` helper enforces the signed deadline.
library Errors {
    function require_EXPIRED(bool condition) internal pure {
        if (!condition) revert("expired");
    }
}
contract ErrorHelperDeadline {
    address public signer;
    mapping(address => uint256) public balances;
    function claim(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        Errors.require_EXPIRED(block.timestamp <= deadline);
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, msg.sender, amount, deadline));
        require(ecrecover(digest, v, r, s) == signer, "sig");
        balances[msg.sender] += amount;
    }
}

// The age of a signed timestamp is computed into a local and bounded.
contract BoundedAgeWithdrawal {
    address public secretSigner;
    mapping(address => uint256) public paid;
    function withdraw(uint256 amount, uint256 issuedAt, uint8 v, bytes32 r, bytes32 s) external {
        uint256 age = block.timestamp - issuedAt;
        require(age < 60, "expired");
        bytes32 digest = keccak256(abi.encodePacked(address(this), block.chainid, msg.sender, amount, issuedAt));
        require(ecrecover(digest, v, r, s) == secretSigner, "sig");
        paid[msg.sender] += amount;
    }
}

// A signed validity window checked in one condition.
contract ValidityWindowMint {
    address public signer;
    mapping(address => uint256) public minted;
    function mint(uint256 amount, uint256 validityStartTimestamp, uint256 validityEndTimestamp, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, msg.sender, amount, validityStartTimestamp, validityEndTimestamp));
        require(ecrecover(digest, v, r, s) == signer, "sig");
        require(validityStartTimestamp <= block.timestamp && validityEndTimestamp >= block.timestamp, "window");
        minted[msg.sender] += amount;
    }
}

// The order signature must come from the caller, who cancels its own order.
contract SelfSignedCancel {
    mapping(address => mapping(bytes32 => uint256)) public orderFills;
    function cancelOrder(address tokenGet, uint256 amountGet, uint256 expires, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 hash = keccak256(abi.encodePacked(address(this), tokenGet, amountGet, expires));
        require(ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)), v, r, s) == msg.sender, "sig");
        orderFills[msg.sender][hash] = amountGet;
    }
}

// A signed epoch must equal the channel's current epoch.
contract CurrentEpochTicket {
    struct Channel { uint256 epoch; uint256 index; uint256 balance; }
    mapping(address => Channel) public channels;
    mapping(address => uint256) public earned;
    function redeem(address source, uint256 epoch, uint256 index, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        Channel storage channel = channels[source];
        require(channel.epoch == epoch, "epoch");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, msg.sender, epoch, index, amount));
        require(ecrecover(digest, v, r, s) == source, "sig");
        channel.balance -= amount;
        earned[msg.sender] += amount;
    }
}

// A struct deadline that the signer may set to zero for no expiry.
contract StructOptOutDeadline {
    struct Signature { uint256 deadline; uint8 v; bytes32 r; bytes32 s; }
    address public signer;
    mapping(address => uint256) public credits;
    function redeem(uint256 amount, Signature memory sig) external {
        require(sig.deadline == 0 || sig.deadline >= block.timestamp, "expired");
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, msg.sender, amount, sig.deadline));
        require(ecrecover(digest, sig.v, sig.r, sig.s) == signer, "sig");
        credits[msg.sender] += amount;
    }
}
