use lettre::{SmtpTransport, Transport};
use log::{error, info};

use aws_sdk_ses::config::Credentials;
use aws_sdk_ses::config::{Builder, Region};
use aws_sdk_ses::types::{Body, Content, Destination, Message};
use aws_sdk_ses::Client as SesClient;
use tera::{Context, Tera};

use crate::app::AppConfig;

use super::api::{ApiError, ApiResult};
use super::storage::StorageService;

#[derive(Debug)]
pub struct EmailResult {
    pub message: String,
}

pub struct EmailVars {
    pub key: String,
    pub val: String,
}

pub struct EmailService {
    ses_client: SesClient,
    from_email: String,
    storage: Box<dyn StorageService>,
}

impl EmailService {
    pub fn new(config: &AppConfig, storage: Box<dyn StorageService>) -> Self {
        let region = Region::new(config.aws_region.clone());

        let credentials = Credentials::new(
            config.aws_ses_access_key.clone(),
            config.aws_ses_secret_key.clone(),
            None,
            None,
            "custom",
        );

        let ses_config = Builder::new()
            .region(region)
            .credentials_provider(credentials)
            .build();

        let client = SesClient::from_conf(ses_config);
        let from_email = format!("🛡️ OxideAuth <{}>", config.aws_ses_from);
        Self {
            ses_client: client,
            from_email,
            storage: storage,
        }
    }

    pub async fn send_email(
        &self,
        to_email: &str,
        subject: &str,
        template_name: &str,
        vars: Vec<EmailVars>,
    ) -> ApiResult<EmailResult> {
        let content = match self.storage.get_file(template_name).await {
            Ok(s) => s.to_string(),
            Err(e) => {
                error!("Error reading file, {}, {e}", template_name);
                "".to_string()
            }
        };

        let mut tera = Tera::default();
        tera.add_raw_template(template_name, &content);

        let mut context = Context::new();

        for var in vars.iter() {
            context.insert(&var.key, &var.val);
        }

        let body = match tera.render(template_name, &context) {
            Ok(body) => body,
            Err(e) => return Err(ApiError::new_400(&format!("Template render error: {}", e))),
        };

        let destination = Destination::builder().to_addresses(to_email).build();

        let subject = Content::builder().data(subject).build().unwrap();
        let body = Body::builder()
            .html(Content::builder().data(body).build().unwrap())
            .build();

        let message = Message::builder().subject(subject).body(body).build();

        let send_email_request = self
            .ses_client
            .send_email()
            .source(&self.from_email)
            .destination(destination)
            .message(message)
            .send()
            .await;

        // Send the email
        match send_email_request {
            Ok(res) => {
                info!("Send email Result: {res:?}");
                Ok(EmailResult {
                    message: "Email sent successfully!".to_string(),
                })
            }
            Err(e) => {
                error!("Could not send email: {:?}", e);
                Err(ApiError::new_400(&e.to_string()))
            }
        }
    }
}
