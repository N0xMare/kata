from route import summarize, total_meters


def check(name, got, want):
    if abs(got - want) > 1e-6:
        raise AssertionError(f"{name}: got {got!r}, want {want!r}")


check("total_meters", total_meters([1.0, 2.0]), 4828.02)
check("summarize round-trip", summarize([1.0, 2.0]), 3.0)
check("summarize short", summarize([0.25]), 0.25)
print("ok")
