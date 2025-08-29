use chrono::Datelike;
use chrono::{Duration, Utc};

use crate::config::Config;

pub fn get_year() -> i32 {
    Utc::now().year()
}
