use std::collections::HashSet;

pub fn contains_all<T: Eq + std::hash::Hash>(superset: &[T], subset: &[T]) -> bool {
    let set: HashSet<_> = superset.iter().collect();
    subset.iter().all(|item| set.contains(item))
}
