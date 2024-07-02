use anyhow::{anyhow, Context};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use ssi::dids::resolution;
use tracing::{debug, error};

#[derive(Debug, Clone)]
pub struct Error {
    status: StatusCode,
    body: ErrorBody,
}

#[derive(Debug, Clone)]
pub enum ErrorBody {
    Text(String),
    // Json(serde_json::Value),
}

impl From<resolution::Error> for Error {
    fn from(value: resolution::Error) -> Self {
        Self {
            status: match value {
                resolution::Error::NotFound => StatusCode::NOT_FOUND,
                resolution::Error::RepresentationNotSupported(_) => StatusCode::NOT_ACCEPTABLE,
                resolution::Error::InvalidData(_)
                | resolution::Error::InvalidMethodSpecificId(_)
                | resolution::Error::InvalidOptions
                | resolution::Error::NoRepresentation => StatusCode::BAD_REQUEST,
                resolution::Error::MethodNotSupported(_) => StatusCode::NOT_IMPLEMENTED,
                e @ resolution::Error::Internal(_) => {
                    return Err::<(), _>(e)
                        .context("Internal resolution error")
                        .unwrap_err()
                        .into()
                }
            },
            body: ErrorBody::Text(format!("Resolution failed: {value}")),
        }
    }
}

impl From<resolution::DerefError> for Error {
    fn from(value: resolution::DerefError) -> Self {
        let body = ErrorBody::Text(format!("Dereferencing failed: {value}"));
        let status = match value {
            resolution::DerefError::Resolution(e) => match e {
                resolution::Error::NotFound => StatusCode::NOT_FOUND,
                resolution::Error::RepresentationNotSupported(_) => StatusCode::NOT_ACCEPTABLE,
                resolution::Error::InvalidData(_)
                | resolution::Error::InvalidMethodSpecificId(_)
                | resolution::Error::InvalidOptions
                | resolution::Error::NoRepresentation => StatusCode::BAD_REQUEST,
                resolution::Error::MethodNotSupported(_) => StatusCode::NOT_IMPLEMENTED,
                e @ resolution::Error::Internal(_) => {
                    return Err::<(), _>(e)
                        .context("Internal resolution error")
                        .unwrap_err()
                        .into()
                }
            },
            resolution::DerefError::NotFound | resolution::DerefError::ResourceNotFound(_) => {
                StatusCode::NOT_FOUND
            }
            resolution::DerefError::MissingServiceEndpoint(_) => StatusCode::BAD_REQUEST,
            resolution::DerefError::UnsupportedServiceEndpointMap
            | resolution::DerefError::UnsupportedMultipleServiceEndpoints => {
                StatusCode::NOT_IMPLEMENTED
            }
            e @ resolution::DerefError::ServiceEndpointConstructionFailed(_) => {
                return Err::<(), _>(e)
                    .context("service endpoint construction failed")
                    .unwrap_err()
                    .into()
            }
            resolution::DerefError::FragmentConflict => return anyhow!("Fragment conflict").into(),
            resolution::DerefError::NullDereference => return anyhow!("Null Dereference").into(),
        };

        Self { status, body }
    }
}

impl From<(StatusCode, String)> for Error {
    fn from(e: (StatusCode, String)) -> Error {
        Error {
            status: e.0,
            body: ErrorBody::Text(e.1),
        }
    }
}

impl<'a> From<(StatusCode, &'a str)> for Error {
    fn from(e: (StatusCode, &'a str)) -> Error {
        Error {
            status: e.0,
            body: ErrorBody::Text(e.1.to_owned()),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        error!("{:?}", e);
        Error {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ErrorBody::Text(e.to_string()),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self.body {
            ErrorBody::Text(t) => {
                debug!("{t}");
                (self.status, t).into_response()
            } // ErrorBody::Json(j) => (self.status, axum::Json(j)).into_response(),
        }
    }
}
