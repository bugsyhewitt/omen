// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberately GREEDY (locked-ether) contract.
// "Greedy" (MAIAN, Nikolic et al., 2018) = a contract that can receive
// Ether but has no reachable code path to release it. Funds sent here are
// locked forever. There is a payable deposit but no withdraw / transfer /
// selfdestruct anywhere in the contract.
contract VulnerableGreedy {
    mapping(address => uint256) public balances;

    // Accepts Ether...
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    // ...but the only "read" path never sends Ether out. No withdraw
    // function exists. The Ether is locked.
    function balanceOf(address who) public view returns (uint256) {
        return balances[who];
    }
}
