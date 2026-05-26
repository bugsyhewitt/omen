// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberately SUICIDAL contract.
// Anyone can call kill() and selfdestruct the contract, draining funds
// to an arbitrary recipient. This mirrors the Parity multisig wallet
// incident that MAIAN (Nikolic et al., 2018) was designed to catch.
contract VulnerableSuicidal {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // No access control: anyone can destroy the contract.
    function kill(address payable recipient) public {
        selfdestruct(recipient);
    }

    receive() external payable {}
}
