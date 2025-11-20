use ironauth_macros::{HasActiveFilter, HasId};
use modql::filter::{IntoFilterNodes, ListOptions, OpValString, OrderBys};
use serde::{Deserialize, Serialize};

use crate::{
    core::{
        error::{CoreError, CoreResult},
        traits::filter::OpValIsString,
    },
    store::{
        filter::HasActiveFilter,
        utils::{LIST_LIMIT_DEFAULT, LIST_LIMIT_MAX},
    },
};

/// Represents the combined parameters for list and filter requests, allowing filtering either by a
/// specific list of tags or by a generalized filter struct, but not both simultaneously.
///
/// This structure is typically received from the request body or query string.
///
/// # Type Parameters
///
/// * `F`: The generic filter struct specific to the target entity (e.g., `UserFilter`, `TaskFilter`).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RequestFilterParams<F>
where
    F: Clone,
{
    /// This is used for standard field-based filtering (e.g., equality, range).
    pub fields: Option<F>,

    /// An optional list of tags used for filtering entities that support tag containment queries.
    pub tags: Option<Vec<String>>,
}

impl<F> RequestFilterParams<F>
where
    F: Clone,
{
    pub fn new(tags: Option<Vec<String>>, filter: Option<F>) -> Self {
        Self {
            fields: filter,
            tags,
        }
    }
    pub fn tags(&self) -> Option<Vec<String>> {
        self.tags.clone()
    }

    pub fn filter(&self) -> Option<F> {
        self.fields.clone()
    }

    /// Validates the request parameters, ensuring that the request does not contain both
    /// a `tags` filter and a flattened `filter` struct simultaneously.
    ///
    /// # Returns
    ///
    /// A `CoreResult` containing `Ok((Option<Vec<String>>, Option<F>))` if validation succeeds,
    /// or `Err(CoreError::InvalidParams)` if both filters are present.
    pub fn validate(&self) -> CoreResult<RequestFilterParams<F>> {
        if self.tags.is_some() && self.fields.is_some() {
            return Err(CoreError::InvalidParams(
                "cannot have both filter and tags on params".to_string(),
            ));
        }

        Ok(Self::new(self.tags.clone(), self.fields.clone()))
    }
}

/// A type alias for `modql::filter::ListOptions`, used for standard pagination and sorting.
pub type RequestListOptions = ListOptions;

/// Metadata detailing the list query result.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ListResponseMeta {
    /// The total number of items available for the current filter criteria (ignoring pagination).
    pub total: i64,
    /// The number of items returned in the current data vector.
    pub count: usize,
    /// The offset applied to the query (for pagination).
    pub offset: Option<i64>,
    /// The limit applied to the query (for pagination).
    pub limit: i64,

    pub order_bys: Option<Vec<String>>,
}

/// A standard structure used for returning list results, combining the retrieved data
/// with metadata about the total count and pagination.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ListResponse<T> {
    /// The vector of entities retrieved for the current page/query.
    pub data: Vec<T>,
    /// Metadata detailing the total available items and pagination specifics.
    pub metadata: ListResponseMeta,
}

impl<T> ListResponse<T> {
    /// Creates a new `ListResponse` instance.
    ///
    /// # Arguments
    ///
    /// * `data`: The list of entities retrieved for the current page.
    /// * `total`: The overall count of entities matching the filter criteria (before limit/offset).
    /// * `offset`: The query offset used.
    /// * `limit`: The query limit used.
    ///
    /// # Returns
    ///
    /// A `ListResponse` wrapping the data and calculated metadata.
    pub fn new(data: Vec<T>, total: i64, options: ListOptions) -> Self {
        let count = data.len();

        let limit = options.limit.unwrap_or(LIST_LIMIT_MAX);
        let order_bys = match options.order_bys {
            Some(order_bys) => {
                let mut strings = vec![];

                for order_by in order_bys.order_bys().iter() {
                    strings.push(format!("{order_by}"));
                }

                Some(strings)
            }
            None => Some(vec![]),
        };

        let metadata = ListResponseMeta {
            total,
            count,
            offset: options.offset,
            limit,
            order_bys,
        };

        ListResponse { data, metadata }
    }
}

impl OpValIsString for OpValString {
    /// Attempts to extract the inner String value if the variant is OpValString::Eq.
    fn as_eq_string(&self) -> Option<&str> {
        if let OpValString::Eq(s) = self {
            Some(s)
        } else {
            None
        }
    }
}

mod tests {
    use crate::core::{
        models::project::{ProjectFilter, ProjectListParams},
        traits::{filter::OpValIsString, list::RequestListParams},
    };

    use super::*;
    use anyhow::Result;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn test_op_val_string_in_list_filter() -> Result<()> {
        let filter_id = Uuid::new_v4();
        let filter: RequestFilterParams<ProjectFilter> = serde_json::from_value(
            json!({"tags":[],"fields":{"workspace_id":filter_id.to_string()}}),
        )
        .unwrap();

        let params = ProjectListParams {
            filter: Some(filter),
            options: None,
        };

        let filter = params.filter().unwrap();
        let fields = filter.fields.unwrap();

        let fields_ws_id = fields
            .workspace_id
            .unwrap()
            .0
            .first()
            .unwrap()
            .as_eq_string()
            .unwrap()
            .to_string();
        assert_eq!(filter_id.to_string(), fields_ws_id);

        let id = params.workspace_id().unwrap();
        assert_eq!(filter_id, id);
        Ok(())
    }

    #[test]
    fn test_list_options() -> Result<()> {
        let filter_id = Uuid::new_v4();
        let filter: RequestFilterParams<ProjectFilter> = serde_json::from_value(
            json!({"tags":[],"fields":{"workspace_id":filter_id.to_string()}}),
        )
        .unwrap();
        let options_input: RequestListOptions =
            serde_json::from_value(json!({"limit":2,"offset":1,"order_bys":["created_at"]}))
                .unwrap();

        let params = ProjectListParams {
            filter: Some(filter),
            options: Some(options_input),
        };

        let options_expected = params.options();

        let id = params.workspace_id();
        assert_eq!(Some(filter_id), id);
        Ok(())
    }
}
