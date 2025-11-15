use modql::filter::ListOptions;
use serde::{Deserialize, Serialize};

use crate::core::error::{CoreError, CoreResult};

#[derive(Serialize, Deserialize, Clone)]
pub struct RequestFilterParams<F>
where
    F: Clone,
{
    pub tags: Option<Vec<String>>,
    #[serde(flatten)]
    pub filter: Option<F>,
}

impl<F> RequestFilterParams<F>
where
    F: Clone,
{
    pub fn validate(&self) -> CoreResult<(Option<Vec<String>>, Option<F>)> {
        if self.tags.is_some() && self.filter.is_some() {
            return Err(CoreError::InvalidParams(
                "cannot have both filter and tags on params".to_string(),
            ));
        }

        Ok((self.tags.clone(), self.filter.clone()))
    }
}

pub type RequestListOptions = ListOptions;
