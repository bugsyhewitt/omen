// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberately broken ACCESS CONTROL.
//
// `owner` is the privileged state variable that gates every admin action,
// yet `setOwner` lets ANYONE overwrite it with no `onlyOwner` (or any) check
// and emits no event when ownership changes. This is the canonical missing-
// access-control bug: an attacker calls setOwner(attacker) and takes over.
//
// `owner` is annotated as write-protected by `onlyOwner()`, declaring the
// security contract that ALL writes to it must go through that modifier. But
// `setOwner` writes `owner` with no modifier at all, breaking that contract.
//
// Slither flags this via the `protected-vars` detector (HIGH impact, HIGH
// confidence): a variable marked write-protection="onlyOwner()" is written by
// an unprotected function — the canonical missing-access-control bug.
contract VulnerableAccessControl {
    /// @custom:security write-protection="onlyOwner()"
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // BUG: no access control. Anyone can seize ownership — `owner` is written
    // here without going through `onlyOwner()`, violating its write-protection.
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // A privileged action that trusts `owner`. Because owner can be hijacked
    // above, this guard is meaningless.
    function withdraw(address payable to) public onlyOwner {
        to.transfer(address(this).balance);
    }

    receive() external payable {}
}
