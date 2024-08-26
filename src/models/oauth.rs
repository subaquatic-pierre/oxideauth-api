use crate::app::AppConfig;

#[derive(Debug)]
pub struct GoogleOAuthState {
    pub csrf_token: String,
    pub redirect_url: String,
    pub dash_url: String,
    pub project_name: String,
}

impl GoogleOAuthState {
    pub fn from_state(state: Option<String>, config: &AppConfig) -> Self {
        let (redirect_url, csrf_token, dash_url, project_name) = match state {
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

                let project_name = match split.get(3) {
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
                    project_name,
                )
            }
            None => (
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
            project_name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppConfig;

    fn default_config() -> AppConfig {
        AppConfig::mock_config()
    }

    #[test]
    fn test_from_state_with_valid_data() {
        let config = default_config();
        let state = Some("redirect_url=http://example.com&csrf_token=abc123&dash_url=http://dashboard.com&project_name=TestProject".to_string());

        let google_oauth_state = GoogleOAuthState::from_state(state, &config);

        assert_eq!(google_oauth_state.redirect_url, "http://example.com");
        assert_eq!(google_oauth_state.csrf_token, "abc123");
        assert_eq!(google_oauth_state.dash_url, "http://dashboard.com");
        assert_eq!(google_oauth_state.project_name, "TestProject");
    }

    #[test]
    fn test_from_state_with_empty_state() {
        let config = default_config();
        let state = None;

        let google_oauth_state = GoogleOAuthState::from_state(state, &config);

        assert_eq!(google_oauth_state.redirect_url, "");
        assert_eq!(google_oauth_state.csrf_token, "");
        assert_eq!(google_oauth_state.dash_url, "");
        assert_eq!(google_oauth_state.project_name, "");
    }
}
