use chrono::Datelike;
use chrono::{Duration, Utc};

use crate::app::AppConfig;

pub fn get_year() -> i32 {
    Utc::now().year()
}
