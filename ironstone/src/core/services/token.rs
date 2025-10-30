use axum::{
    extract::Request,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
};

pub struct TokenService;

impl TokenService {
    pub fn token_from_req<'a>(req: &'a Request) -> Option<&'a str> {
        let headers = req.headers();

        let auth_header = headers.get(AUTHORIZATION).and_then(|h| h.to_str().ok());

        let token = match auth_header {
            Some(str) => {
                let mut iter = str.split(" ").into_iter();

                let start = iter.next();
                let token = iter.next();
                token
            }
            None => None,
        };

        token
    }
}
