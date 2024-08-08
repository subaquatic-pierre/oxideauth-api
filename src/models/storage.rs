use core::str;
// Define the StorageService trait
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

// Create fake "file"

use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::config::{Builder, Region};
use aws_sdk_s3::Client as S3Client;
use log::{debug, error, info};

use crate::app::AppConfig;

#[async_trait]
pub trait StorageService {
    async fn get_file(&self, template_name: &str) -> Result<String, Box<dyn Error>>;
}

// Implement the StorageService trait for LocalStorage
pub struct LocalStorageService {
    base_dir: String,
}

impl LocalStorageService {
    pub fn new(base_dir: &str) -> Self {
        Self {
            base_dir: base_dir.to_string(),
        }
    }
}

#[async_trait]
impl StorageService for LocalStorageService {
    async fn get_file(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        let path = format!("{}/{filename}", self.base_dir);
        let path = Path::new(&path);
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents);
        Ok(contents)
    }
}

pub struct S3StorageService {
    s3_client: S3Client,
    bucket_name: String,
}

impl S3StorageService {
    pub fn new(bucket_name: &str, config: &AppConfig) -> Self {
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

        Self {
            s3_client,
            bucket_name: bucket_name.to_string(),
        }
    }
}

#[async_trait]
impl StorageService for S3StorageService {
    async fn get_file(&self, filename: &str) -> Result<String, Box<dyn Error>> {
        let mut object = self
            .s3_client
            .get_object()
            .bucket(&self.bucket_name)
            .key(filename)
            .send()
            .await?;

        let mut file = Cursor::new(Vec::new());

        while let Some(bytes) = object.body.try_next().await? {
            file.write_all(&bytes)?;
        }

        let bytes = file.into_inner();
        let contents = str::from_utf8(&bytes)?;

        Ok(contents.to_string())
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum StorageServiceType {
    Local,
    S3,
}
