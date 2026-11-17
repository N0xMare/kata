/// A folding accumulator. Implementors decide how values combine.
pub trait Fold {
    /// The identity: folding it with anything returns the other value.
    fn identity() -> Self;
    /// Combine two values. Must be associative.
    fn combine(self, other: Self) -> Self;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MinMax {
    pub min: i64,
    pub max: i64,
}

impl MinMax {
    pub fn singleton(v: i64) -> Self {
        MinMax { min: v, max: v }
    }
}

impl Fold for MinMax {
    fn identity() -> Self {
        // TODO: an identity such that combine(identity(), x) == x for every x.
        MinMax { min: 0, max: 0 }
    }

    fn combine(self, other: Self) -> Self {
        // TODO: combine two ranges.
        self
    }
}

pub fn fold_all<T: Fold>(items: Vec<T>) -> T {
    let mut acc = T::identity();
    for item in items {
        acc = acc.combine(item);
    }
    acc
}

#[test]
fn folds_a_range() {
    let got = fold_all(vec![
        MinMax::singleton(3),
        MinMax::singleton(-7),
        MinMax::singleton(12),
    ]);
    assert_eq!(got, MinMax { min: -7, max: 12 });
}

#[test]
fn identity_is_neutral_on_negatives() {
    let x = MinMax { min: -5, max: -2 };
    assert_eq!(MinMax::identity().combine(x), x);
    assert_eq!(x.combine(MinMax::identity()), x);
}

#[test]
fn empty_fold_is_the_identity() {
    let empty: Vec<MinMax> = vec![];
    assert_eq!(fold_all(empty), MinMax::identity());
}
