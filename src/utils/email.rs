// use lettre::message::{header, Mailbox, Message};
// use lettre::transport::smtp::authentication::Credentials;
use lettre::{SmtpTransport, Transport};
use log::{error, info};

use aws_sdk_ses::config::Credentials;
use aws_sdk_ses::config::{Builder, Region};
use aws_sdk_ses::types::{Body, Content, Destination, Message};
use aws_sdk_ses::Client;
use tera::{Context, Tera};

use crate::app::AppConfig;
use crate::models::api::{ApiError, ApiResult};

#[derive(Debug)]
pub struct EmailResult {
    pub message: String,
}

pub struct EmailVars {
    pub key: String,
    pub val: String,
}

pub async fn send_email(
    config: &AppConfig,
    to_email: &str,
    subject: &str,
    template_name: &str,
    vars: Vec<EmailVars>,
) -> ApiResult<EmailResult> {
    let from_email = format!("🛡️ OxideAuth <{}>", config.aws_ses_from);
    let tera: Tera = match Tera::new("templates/*.html") {
        Ok(t) => t,
        Err(e) => return Err(ApiError::new_400(&format!("Parsing error: {}", e))),
    };

    let mut context = Context::new();

    for var in vars.iter() {
        context.insert(&var.key, &var.val);
    }

    let body = match tera.render(template_name, &context) {
        Ok(body) => body,
        Err(e) => return Err(ApiError::new_400(&format!("Template render error: {}", e))),
    };

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

    let client = Client::from_conf(ses_config);

    let destination = Destination::builder().to_addresses(to_email).build();

    let subject = Content::builder().data(subject).build().unwrap();
    let body = Body::builder()
        .html(Content::builder().data(body).build().unwrap())
        .build();

    let message = Message::builder().subject(subject).body(body).build();

    let send_email_request = client
        .send_email()
        .source(from_email)
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

// pub fn send_email(
//     config: &AppConfig,
//     to_email: &str,
//     subject: &str,
//     body: &str,
// ) -> ApiResult<EmailResult> {
//     let email = Message::builder()
//         .from(config.aws_ses_from.parse().unwrap())
//         .reply_to(config.aws_ses_from.parse().unwrap())
//         .to(to_email.parse().unwrap())
//         .subject(subject.to_string())
//         .header(header::ContentType::TEXT_HTML)
//         .body(body.to_string())
//         .unwrap();

//     info!("{config:?}");
//     let creds = Credentials::new(
//         config.aws_ses_access_key.to_string(),
//         config.aws_ses_secret_key.to_string(),
//     );

//     // Open a remote connection to an SMTP relay server
//     let mailer = SmtpTransports::relay(&config.aws_ses_host)
//         .unwrap()
//         .port(465)
//         .credentials(creds)
//         .build();

//     // Send the email
//     match mailer.send(&email) {
//         Ok(res) => {
//             info!("Send email Result: {res:?}");
//             Ok(EmailResult {
//                 message: "Email sent successfully!".to_string(),
//             })
//         }
//         Err(e) => {
//             error!("Could not send email: {:?}", e);
//             Err(ApiError::new_400(&e.to_string()))
//         }
//     }
// }
