"""A tiny running-balance ledger."""


class Ledger:
    def __init__(self, opening=0):
        self.opening = opening
        self.entries = []

    def post(self, amount):
        self.entries.append(amount)
        return self.balance()

    def balance(self):
        total = self.opening
        for amount in self.entries:
            total += amount
        return total

    def reversed_entries(self):
        """Entries newest-first. Callers must not be able to mutate our state."""
        return list(reversed(self.entries))
