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
