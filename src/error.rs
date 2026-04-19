// Typed error hierarchy kept for documentation and future refactor targets;
// runtime paths currently use ad-hoc JSON shapes in handlers.
#![allow(dead_code)]

use serde::Serialize;

/// Application error types mapped to HTTP status codes.
#[derive(Debug)]
pub enum AppError {
    /// 400 — bad input
    ValidationError(String),
    /// 401 — missing or invalid auth
    Unauthorized(String),
    /// 403 — blocked by permissions
    Forbidden(String),
    /// 404 — resource not found
    NotFound(String),
    /// 409 — duplicate resource
    Conflict(String),
    /// 500 — internal
    InternalError(String),
}

impl AppError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::ValidationError(_) => 400,
            Self::Unauthorized(_) => 401,
            Self::Forbidden(_) => 403,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::InternalError(_) => 500,
        }
    }

    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ValidationError(_) => "ERR_VALIDATION",
            Self::Unauthorized(_) => "ERR_UNAUTHORIZED",
            Self::Forbidden(_) => "ERR_DELIVERY_BLOCKED",
            Self::NotFound(_) => "ERR_NOT_FOUND",
            Self::Conflict(_) => "ERR_DUPLICATE_MESSAGE",
            Self::InternalError(_) => "ERR_INTERNAL",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::ValidationError(m)
            | Self::Unauthorized(m)
            | Self::Forbidden(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::InternalError(m) => m,
        }
    }
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub status: &'static str,
    pub code: &'static str,
    pub description: String,
}

impl From<&AppError> for ErrorResponse {
    fn from(e: &AppError) -> Self {
        Self {
            status: "error",
            code: e.error_code(),
            description: e.message().to_string(),
        }
    }
}
