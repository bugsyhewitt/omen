// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberate attacker-controlled delegatecall.
//
// forward() takes the delegatecall TARGET as a function argument and
// delegatecalls into it. delegatecall runs the callee's code in THIS
// contract's storage, balance, and msg.sender context, so an attacker who
// controls `target` can overwrite any state variable (e.g. `owner`) or even
// selfdestruct the contract. This is the canonical "controlled delegatecall"
// bug behind the second Parity multisig freeze.
//
// Slither flags this via the `controlled-delegatecall` detector.
contract VulnerableDelegatecall {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // BUG: `target` is caller-controlled and reached by delegatecall.
    function forward(address target, bytes memory data) public {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    receive() external payable {}
}
