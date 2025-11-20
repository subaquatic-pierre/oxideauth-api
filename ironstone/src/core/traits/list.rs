use modql::filter::IntoFilterNodes;
use uuid::Uuid;

use crate::{
    core::{
        error::CoreResult,
        models::list::{RequestFilterParams, RequestListOptions},
    },
    store::utils::ListOptionsValidator,
};

pub trait RequestListParams<F: IntoFilterNodes + Clone> {
    fn filter(&self) -> Option<RequestFilterParams<F>>;
    fn options(&self) -> Option<RequestListOptions>;
    fn workspace_id(&self) -> Option<Uuid>;

    fn list_options(&self) -> RequestListOptions {
        let options = self.options().unwrap_or_else(ListOptionsValidator::default);
        options
    }

    fn validate_filter_tags(&self) -> CoreResult<RequestFilterParams<F>> {
        let filter = self.filter();
        let params = match filter {
            Some(filter) => filter.validate()?,
            None => RequestFilterParams::new(None, None),
        };

        Ok(params)
    }
}
