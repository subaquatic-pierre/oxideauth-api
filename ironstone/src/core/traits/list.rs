use modql::filter::{IntoFilterNodes, OpValsString};
use uuid::Uuid;

use crate::{
    core::{
        error::CoreResult,
        models::list::{RequestFilterParams, RequestListOptions},
        traits::modql::OpValIsString,
    },
    store::utils::ListOptionsValidator,
};

// 1. Define the requirement for a filter structure
pub trait HasWorkspaceId {
    /// Must return a reference to the Option<OpValsString> for workspace_id.
    fn get_workspace_id_opvals(&self) -> Option<&OpValsString>;
}

pub trait RequestListParams<F: IntoFilterNodes + Clone + HasWorkspaceId> {
    fn filter(&self) -> Option<RequestFilterParams<F>>;
    fn options(&self) -> Option<RequestListOptions>;

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

    fn workspace_id(&self) -> Option<Uuid> {
        self.filter()
            .as_ref()
            .and_then(|filter| filter.fields.as_ref())
            .and_then(|fields| fields.get_workspace_id_opvals()) // Use the new trait method
            .and_then(|op_vals| {
                // We only care about the first operator value (op_vals.0 is Vec<OpValString>)
                op_vals.0.first()
            })
            // Only proceed if the operator is OpValString::Eq and contains a string
            .and_then(|op_val_string| op_val_string.as_eq_string()) // Assuming OpValString::as_eq_string() exists
            // Attempt to parse the resulting string as a Uuid
            .and_then(|val_str| Uuid::try_parse(val_str).ok())
    }
}
