/// Return the inclusive sum 1 + 2 + ... + n.
pub fn sum_to_n(n: u64) -> u64 {
    // BUG: the loop stops before n, so the result excludes n.
    let mut total = 0;
    let mut i = 0;
    while i < n {
        total += i;
        i += 1;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_inclusive() {
        assert_eq!(sum_to_n(1), 1);
        assert_eq!(sum_to_n(5), 15);
        assert_eq!(sum_to_n(10), 55);
    }
}
