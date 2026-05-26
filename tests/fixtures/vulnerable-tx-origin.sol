// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberate TX.ORIGIN authentication misuse.
//
// transferTo() authenticates the caller with `tx.origin` instead of
// `msg.sender`. tx.origin is the original externally-owned account that
// started the transaction, NOT the immediate caller. If the owner is tricked
// into calling a malicious contract, that contract can call transferTo() and
// the `tx.origin == owner` check passes — draining the wallet. This is the
// classic phishing-relay attack.
//
// Slither flags this via the `tx-origin` detector.
contract VulnerableTxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BUG: uses tx.origin for authorization. An attacker contract the owner
    // is lured into calling can invoke this and pass the check.
    function transferTo(address payable dest, uint256 amount) public {
        require(tx.origin == owner, "not owner");
        dest.transfer(amount);
    }

    receive() external payable {}
}
