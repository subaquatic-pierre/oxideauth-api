#[derive(Debug)]
pub struct GoogleOAuthState {
    pub csrf_token: String,
    pub redirect_url: String,
}

impl GoogleOAuthState {
    pub fn from_state(state: Option<String>) -> Self {
        let (url, token) = match state {
            Some(s) => {
                let split: Vec<&str> = s.split("&").collect();

                let url_split: Vec<&str> = split[0].split("=").collect();
                let t_split: Vec<&str> = split[1].split("=").collect();

                (url_split[1].to_string(), t_split[1].to_string())
            }
            None => ("".to_string(), "".to_string()),
        };

        Self {
            csrf_token: token,
            redirect_url: url,
        }
    }
}
