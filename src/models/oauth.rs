use crate::app::AppConfig;

#[derive(Debug)]
pub struct GoogleOAuthState {
    pub csrf_token: String,
    pub redirect_url: String,
    pub dash_url: String,
    pub logo_url: String,
    pub project_name: String,
}

impl GoogleOAuthState {
    pub fn from_state(state: Option<String>, config: &AppConfig) -> Self {
        let (redirect_url, csrf_token, dash_url, logo_url, project_name) = match state {
            Some(s) => {
                let split: Vec<&str> = s.split("&").collect();

                let url_split: Vec<&str> = split[0].split("=").collect();
                let token_split: Vec<&str> = split[1].split("=").collect();

                let dash_url = match split.get(2) {
                    Some(&str) => {
                        let split: Vec<&str> = str.split("=").collect();
                        split[1].to_string()
                    }
                    None => format!("{}/dashboard", config.client_origin).to_string(),
                };

                let logo_url = match split.get(3) {
                    Some(&str) => {
                        let split: Vec<&str> = str.split("=").collect();
                        split[1].to_string()
                    }
                    None => "https://oxideauth.nebuladev.io/brand/logoIconText.png".to_string(),
                };

                let project_name = match split.get(4) {
                    Some(&str) => {
                        let split: Vec<&str> = str.split("=").collect();
                        split[1].to_string()
                    }
                    None => "OxideAuth".to_string(),
                };

                (
                    url_split[1].to_string(),
                    token_split[1].to_string(),
                    dash_url,
                    logo_url,
                    project_name,
                )
            }
            None => (
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
                "".to_string(),
            ),
        };

        Self {
            redirect_url,
            csrf_token,
            dash_url,
            logo_url,
            project_name,
        }
    }
}
