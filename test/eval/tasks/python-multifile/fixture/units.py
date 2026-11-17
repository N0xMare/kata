"""Unit conversion helpers."""

METERS_PER_MILE = 1609.34


def miles_to_meters(miles):
    return miles * METERS_PER_MILE


def meters_to_miles(meters):
    # BUG: multiplies where it should divide.
    return meters * METERS_PER_MILE
