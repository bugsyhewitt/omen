// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: a clean contract that should produce NO delegatecall or
// upgrade findings.
//
// It delegatecalls only to a FIXED, compile-time-constant library address with
// a hardcoded function selector. Slither's controlled-delegatecall detector
// fires when either the target OR the function id can be influenced by input
// (or by mutable state an attacker could change); a `constant` address with a
// literal selector is influenced by neither, so the detector stays silent.
// The contract is not upgradeable/initializable, so there is no
// unprotected-upgrade either. This guards against false positives.
contract CleanDelegatecall {
    address public owner;

    // Fixed, compile-time-constant trusted library. Not caller-controlled and
    // not mutable, so a delegatecall to it is not "controlled".
    address constant LIB = 0x000000000000000000000000000000000000dEaD;

    constructor() {
        owner = msg.sender;
    }

    function poke() public {
        require(msg.sender == owner, "not owner");
        (bool ok, ) = LIB.delegatecall(abi.encodeWithSignature("ping()"));
        require(ok, "call failed");
    }

    receive() external payable {}
}
