# omen test fixture: deliberately REENTRANT Vyper contract (POST_V01 Rank 6).
#
# The classic withdraw-before-state-update bug: the external value transfer
# (raw_call with value) happens BEFORE the caller's balance is zeroed, so a
# malicious fallback can re-enter withdraw() and drain the contract. This is
# the Vyper analogue of tests/fixtures/vulnerable-reentrancy.sol and exercises
# Slither's Vyper front-end (reentrancy is in the supported subset).
#
# No `# @version` pragma on purpose: there is no solc-select equivalent for
# vyper, so the fixture must compile on whatever vyper the test environment
# provides. The reentrancy shape below is stable across vyper 0.3.x/0.4.x.

balances: public(HashMap[address, uint256])


@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value


@external
def withdraw():
    amount: uint256 = self.balances[msg.sender]
    assert amount > 0, "no balance"

    # Vulnerable: external call before state update.
    raw_call(msg.sender, b"", value=amount)

    # State update happens AFTER the external call -> reentrancy.
    self.balances[msg.sender] = 0


@external
@payable
def __default__():
    pass
