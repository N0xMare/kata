from ledger import Ledger


def check(name, got, want):
    if got != want:
        raise AssertionError(f"{name}: got {got!r}, want {want!r}")


led = Ledger(opening=100)
led.post(10)
led.post(-30)
check("balance", led.balance(), 80)
check("reversed_entries", led.reversed_entries(), [-30, 10])
check("balance survives reversed_entries", led.balance(), 80)
check("entries unmutated", led.entries, [10, -30])
print("ok")
