use crate::store::meta::{MutateStore, ReadStore};

pub trait CrudStore: MutateStore + ReadStore {}
