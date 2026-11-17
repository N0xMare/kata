/// Return `s` with its characters in reverse order.
pub fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses() {
        assert_eq!(reverse("abc"), "cba");
        assert_eq!(reverse(""), "");
        assert_eq!(reverse("kata"), "atak");
    }
}
