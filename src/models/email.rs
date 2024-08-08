use lettre::{SmtpTransport, Transport};
use log::{error, info};

use aws_sdk_ses::config::Credentials;
use aws_sdk_ses::config::{Builder, Region};
use aws_sdk_ses::types::{Body, Content, Destination, Message};
use aws_sdk_ses::Client as SesClient;
use tera::{Context, Tera};

use crate::app::AppConfig;

use super::api::ApiError;

pub struct EmailService {
    ses_client: SesClient,
    from_email: String,
}

impl EmailService {
    fn new(config: AppConfig) -> Self {
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
        Self {
            ses_client: client,
            from_email: config.aws_ses_from,
        }
    }

    fn send_email(&self) {
        // let tera: Tera = match Tera::new("templates/*.html") {
        //     Ok(t) => t,
        //     Err(e) => return Err(ApiError::new_400(&format!("Parsing error: {}", e))),
        // };

        // let mut context = Context::new();

        // for var in vars.iter() {
        //     context.insert(&var.key, &var.val);
        // }

        // let body = match tera.render(template_name, &context) {
        //     Ok(body) => body,
        //     Err(e) => return Err(ApiError::new_400(&format!("Template render error: {}", e))),
        // };

        // let destination = Destination::builder().to_addresses(to_email).build();

        // let subject = Content::builder().data(subject).build().unwrap();
        // let body = Body::builder()
        //     .html(Content::builder().data(body).build().unwrap())
        //     .build();

        // let message = Message::builder().subject(subject).body(body).build();

        // let send_email_request = client
        //     .send_email()
        //     .source(from_email)
        //     .destination(destination)
        //     .message(message)
        //     .send()
        //     .await;

        // // Send the email
        // match send_email_request {
        //     Ok(res) => {
        //         info!("Send email Result: {res:?}");
        //         Ok(EmailResult {
        //             message: "Email sent successfully!".to_string(),
        //         })
        //     }
        //     Err(e) => {
        //         error!("Could not send email: {:?}", e);
        //         Err(ApiError::new_400(&e.to_string()))
        //     }
        // }
    }
}
