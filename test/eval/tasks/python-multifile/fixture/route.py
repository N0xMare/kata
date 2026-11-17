"""Route totals, built on units.py."""

from units import meters_to_miles, miles_to_meters


def total_meters(legs_in_miles):
    return sum(miles_to_meters(leg) for leg in legs_in_miles)


def summarize(legs_in_miles):
    meters = total_meters(legs_in_miles)
    # BUG: rounds before converting, so short routes collapse to 0.
    return round(meters_to_miles(round(meters)), 4)
