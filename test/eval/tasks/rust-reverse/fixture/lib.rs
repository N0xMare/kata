/// Return `s` with its characters in reverse order.
pub fn reverse(s: &str) -> String {
    // TODO: implement.
    let _ = s;
    String::new()
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
