// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberately REENTRANT contract.
// The classic withdraw-before-state-update bug behind the DAO hack:
// the external call (msg.sender.call) happens BEFORE balances are zeroed,
// so a malicious fallback can re-enter withdraw() and drain the contract.
contract VulnerableReentrancy {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable: external call before state update.
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        // State update happens AFTER the external call -> reentrancy.
        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
