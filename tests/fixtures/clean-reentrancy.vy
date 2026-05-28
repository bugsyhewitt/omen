# omen test fixture: CEI-compliant (NON-reentrant) Vyper contract.
#
# State is zeroed BEFORE the external value transfer, so a re-entrant call
# sees a zero balance and cannot drain the contract. Used as the negative
# control for the Vyper reentrancy detection test (POST_V01 Rank 6).

balances: public(HashMap[address, uint256])


@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value


@external
def withdraw():
    amount: uint256 = self.balances[msg.sender]
    assert amount > 0, "no balance"

    # Effects before interactions: zero the balance first.
    self.balances[msg.sender] = 0
    raw_call(msg.sender, b"", value=amount)


@external
@payable
def __default__():
    pass
