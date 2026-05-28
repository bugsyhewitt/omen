// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// omen test fixture: deliberate weak on-chain PRNG.
//
// pickWinner() derives a "random" index from block.timestamp and
// blockhash(block.number - 1). Both are observable and manipulable by the
// block proposer (and predictable within the same transaction), so an attacker
// can force a favorable outcome. This is the canonical weak-randomness bug the
// omen `weak-randomness` class targets via Slither's `weak-prng` detector.
contract VulnerableWeakRandomness {
    uint256 public players;

    function pickWinner() public view returns (uint256) {
        // BUG: block.timestamp + blockhash used as a randomness source.
        uint256 seed = uint256(
            keccak256(
                abi.encodePacked(block.timestamp, blockhash(block.number - 1))
            )
        );
        return seed % players;
    }
}
