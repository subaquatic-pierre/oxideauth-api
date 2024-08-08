// Define the StorageService trait
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::config::{Builder, Region};
use aws_sdk_s3::Client as S3Client;

use crate::app::AppConfig;
pub trait StorageService {
    async fn get_template(&self, template_name: &str) -> Result<String, Box<dyn Error>>;
}

// Implement the StorageService trait for LocalStorage
pub struct LocalStorage {
    base_dir: String,
}

impl LocalStorage {
    pub async fn new(base_dir: &str) -> Self {
        Self {
            base_dir: base_dir.to_string(),
        }
    }
}

impl StorageService for LocalStorage {
    async fn get_template(&self, template_name: &str) -> Result<String, Box<dyn Error>> {
        let path = format!("{}/{template_name}", self.base_dir);
        let path = Path::new(&path);
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents);
        Ok(contents)
    }
}

pub struct S3Storage {
    s3_client: S3Client,
    bucket_name: String,
}

impl S3Storage {
    pub async fn new(bucket_name: &str, config: AppConfig) -> Self {
        let credentials = Credentials::new(
            config.aws_s3_access_key.to_string(),
            config.aws_s3_secret_key.to_string(),
            None,
            None,
            "custom",
        );

        let region = Region::new(config.aws_region.to_string());

        let s3_config = Builder::new()
            .region(region)
            .credentials_provider(credentials)
            .build();

        let s3_client = S3Client::from_conf(s3_config);
        // let config = aws_config::load_from_env().await;
        // let client = aws_sdk_s3::Client::new(&config);
        S3Storage {
            s3_client,
            bucket_name: bucket_name.to_string(),
        }
    }
}
