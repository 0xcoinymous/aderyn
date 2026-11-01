// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Not signature logic: an ERC-721 receiver check that accepts accounts without code.
interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
}

contract ReceiverCheck {
    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data) internal returns (bool) {
        if (to.code.length == 0) return true;
        try IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data) returns (bytes4 retval) {
            return retval == IERC721Receiver.onERC721Received.selector;
        } catch {
            return false;
        }
    }

    function safeTransfer(address to, uint256 tokenId) external {
        require(_checkOnERC721Received(msg.sender, to, tokenId, ""), "receiver");
    }
}
