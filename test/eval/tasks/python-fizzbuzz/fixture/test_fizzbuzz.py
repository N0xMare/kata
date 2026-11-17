from fizzbuzz import fizzbuzz


def main():
    out = fizzbuzz(15)
    assert len(out) == 15, f"len {len(out)} != 15"
    assert out[0] == "1", out[0]
    assert out[1] == "2", out[1]
    assert out[2] == "Fizz", out[2]
    assert out[4] == "Buzz", out[4]
    assert out[14] == "FizzBuzz", out[14]
    print("ok")


if __name__ == "__main__":
    main()
