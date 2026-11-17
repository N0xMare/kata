from stats import median


def main():
    assert median([1, 2, 3]) == 2, median([1, 2, 3])
    assert median([5]) == 5, median([5])
    assert median([1, 2, 3, 4]) == 2.5, median([1, 2, 3, 4])
    assert median([7, 1, 3]) == 3, median([7, 1, 3])
    print("ok")


if __name__ == "__main__":
    main()
