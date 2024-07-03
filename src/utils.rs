use std::str::FromStr;

use anyhow::{anyhow, bail};
use axum::{
    async_trait,
    extract::{rejection::JsonRejection, FromRequest},
    http::{header::ACCEPT, Request, StatusCode},
};
use axum_extra::headers::Header;
use serde::{Deserialize, Serialize};
use ssi::{
    claims::data_integrity::{AnyInputOptions, AnySuite},
    jwk::{Algorithm, JWK},
    verification_methods::ProofPurpose,
};
use tracing::debug;

pub struct CustomErrorJson<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for CustomErrorJson<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, body);

        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(Self(value.0)),
            Err(rejection) => {
                let message = rejection.to_string();
                let code = if let JsonRejection::JsonDataError(_) = rejection {
                    StatusCode::BAD_REQUEST
                } else {
                    rejection.status()
                };
                debug!("JSON rejection: {message}");
                Err((code, message))
            }
        }
    }
}

// https://w3c-ccg.github.io/vc-http-api/#/Verifier/verifyCredential
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// Object summarizing a verification
/// Reference: vc-http-api
pub struct VerificationResult {
    /// The checks performed
    pub checks: Vec<Check>,
    /// Warnings
    pub warnings: Vec<String>,
    /// Errors
    pub errors: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Check {
    Proof,
    #[serde(rename = "JWS")]
    Jws,
    Status,
}

impl FromStr for Check {
    type Err = anyhow::Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "proof" => Ok(Self::Proof),
            "JWS" => Ok(Self::Jws),
            "credentialStatus" => Ok(Self::Status),
            _ => Err(anyhow!("Unsupported check")),
        }
    }
}

impl TryFrom<String> for Check {
    type Error = anyhow::Error;
    fn try_from(purpose: String) -> Result<Self, Self::Error> {
        Self::from_str(&purpose)
    }
}

impl From<Check> for String {
    fn from(check: Check) -> String {
        match check {
            Check::Proof => "proof".to_string(),
            Check::Jws => "JWS".to_string(),
            Check::Status => "credentialStatus".to_string(),
        }
    }
}

pub struct Accept(String);

impl Accept {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Header for Accept {
    fn name() -> &'static axum::http::HeaderName {
        &ACCEPT
    }

    fn encode<E: Extend<axum::http::HeaderValue>>(&self, values: &mut E) {
        values.extend(Some(self.0.clone().try_into().unwrap()))
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i axum::http::HeaderValue>,
    {
        let bytes = values.next().ok_or(axum_extra::headers::Error::invalid())?;

        if values.next().is_none() {
            let str = bytes
                .to_str()
                .map_err(|_| axum_extra::headers::Error::invalid())?;
            Ok(Self(str.to_owned()))
        } else {
            Err(axum_extra::headers::Error::invalid())
        }
    }
}

impl PartialEq<str> for Accept {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl<'a> PartialEq<&'a str> for Accept {
    fn eq(&self, other: &&'a str) -> bool {
        self.0 == *other
    }
}

pub fn pick_from_jwk(jwk: &JWK) -> Result<String, anyhow::Error> {
    match jwk.get_algorithm() {
        Some(Algorithm::EdDSA) => Ok("eddsa-2022".to_string()),
        Some(Algorithm::ES256) | Some(Algorithm::ES384) => Ok("ecdsa-2019".to_string()),
        Some(Algorithm::None) | None => bail!("Missing algorithm"),
        Some(_) => bail!("Unsupported cryptosuite"),
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct JWTOrLDPOptions {
    /// Linked data proof options from vc-api (vc-http-api)
    ///
    /// See: <https://w3c-ccg.github.io/vc-api/#options>
    #[serde(flatten)]
    pub ldp_options: LDPOptions,

    /// Proof format (not standard in vc-api)
    #[serde(default, skip_serializing_if = "ProofFormat::is_default")]
    pub proof_format: ProofFormat,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LDPOptions {
    #[serde(rename = "type")]
    pub type_: Option<String>,

    pub cryptosuite: Option<String>,

    #[serde(flatten)]
    pub input_options: AnyInputOptions,
}

impl LDPOptions {
    pub fn select_suite(&self, jwk: &JWK) -> Option<AnySuite> {
        match self.type_.clone() {
            Some(type_) => Some(
                ssi::claims::data_integrity::Type::new(type_, self.cryptosuite.clone())
                    .unwrap()
                    .into(),
            ),
            None => AnySuite::pick(jwk, self.input_options.verification_method.as_ref()),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
//#[serde(deny_unknown_fields)]
pub struct VerificationOptions {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<Check>,

    /// Proof format (not standard in vc-api)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_format: Option<ProofFormat>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_proof_purpose: Option<ProofPurpose>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[non_exhaustive]
pub enum ProofFormat {
    /// Linked-Data secured credential.
    ///
    /// <https://www.w3.org/TR/vc-data-model/#linked-data-proofs>
    #[serde(rename = "ldp")]
    Ldp,

    /// JWS secured credential.
    ///
    /// <https://www.w3.org/TR/vc-data-model/#json-web-token>
    #[serde(rename = "jwt")]
    Jwt,
}
// ProofFormat implements Display and FromStr for structopt. This should be kept in sync with the
// serde (de)serialization (rename = ...)

impl ProofFormat {
    pub fn is_default(&self) -> bool {
        matches!(self, Self::Ldp)
    }
}

impl Default for ProofFormat {
    fn default() -> Self {
        Self::Ldp
    }
}

impl std::fmt::Display for ProofFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ldp => write!(f, "ldp"),
            Self::Jwt => write!(f, "jwt"),
        }
    }
}

impl FromStr for ProofFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ldp" => Ok(Self::Ldp),
            "jwt" => Ok(Self::Jwt),
            _ => Err(format!("Unexpected proof format: {}", s))?,
        }
    }
}
