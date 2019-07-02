#[derive(Serialize)]
pub(crate) struct Claims {
    #[serde(rename = "iss")]
    pub(crate) issuer: String,
    #[serde(rename = "aud")]
    pub(crate) audience: String,
    #[serde(rename = "exp")]
    pub(crate) expiration: i64,
    #[serde(rename = "iat")]
    pub(crate) issued_at: i64,
    pub(crate) sub: Option<String>,
    pub(crate) scope: String,
}
