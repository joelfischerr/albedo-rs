/*
 * Copyright 2026 CRS Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ----------------------------------------------------------------------
 * MODIFICATION NOTICE:
 * This file is a derivative work based on the original Go
 * source code from https://github.com/coreruleset/albedo.
 * ----------------------------------------------------------------------
 */

use axum::{
    body::{Body, Bytes},
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get, post, put},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Type Definitions
// -----------------------------------------------------------------------------

const CAPABILITIES_YAML: &str = include_str!("capabilities.yaml");

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CapabilitiesSpec {
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Endpoint {
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    #[serde(
        default,
        rename = "contentType",
        skip_serializing_if = "String::is_empty"
    )]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReflectionSpec {
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default, rename = "encodedBody")]
    pub encoded_body: String,
    #[serde(default, rename = "logMessage")]
    pub log_message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfigureReflectionSpec {
    #[serde(flatten)]
    pub reflection: ReflectionSpec,
    pub endpoints: Vec<DynamicEndpointSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DynamicEndpointSpec {
    pub method: String,
    pub url: String,
}

#[derive(Deserialize)]
struct CapabilitiesQuery {
    quiet: Option<String>,
    pretty: Option<String>,
}

// -----------------------------------------------------------------------------
// App State
// -----------------------------------------------------------------------------

type SharedState = Arc<RwLock<AppState>>;

#[derive(Clone)]
pub struct LogicState {
    pub dynamic_endpoints: Arc<RwLock<HashMap<(String, String), ReflectionSpec>>>,
    pub capabilities: Arc<RwLock<CapabilitiesSpec>>,
}

struct AppState {
    dynamic_endpoints: HashMap<(String, String), ReflectionSpec>,
    capabilities: CapabilitiesSpec,
}

impl AppState {
    fn new() -> Self {
        let capabilities: CapabilitiesSpec =
            serde_yaml::from_str(CAPABILITIES_YAML).expect("Failed to parse capabilities.yaml");

        Self {
            dynamic_endpoints: HashMap::new(),
            capabilities,
        }
    }
}

// -----------------------------------------------------------------------------
// Public Library API
// -----------------------------------------------------------------------------

/// Builds the Axum router.
/// You can attach middleware to this router using `.layer(...)` before serving.
///
/// We can use multiple different states, so if the middleware comes with its own state this
/// will not be a problem.
pub fn build_router() -> Router {
    let state = Arc::new(RwLock::new(AppState::new()));

    Router::new()
        // Explicit Endpoints
        .route("/capabilities", get(handle_capabilities))
        .route("/reflect", post(handle_reflect))
        .route("/configure_reflection", post(handle_configure_reflection))
        .route("/reset", put(handle_reset))
        // Inspection endpoints
        .route("/inspect", any(handle_inspect))
        .route("/inspect/{*path}", any(handle_inspect))
        // Default Fallback
        .fallback(handle_default)
        .with_state(state)
}

/// Convenience function to start the server on a specific address.
pub async fn start_server(addr: &str) {
    let app = build_router();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("Listening on {}", listener.local_addr().unwrap());
    if let Err(err) = axum::serve(listener, app).await {
        warn!("Server stopped exit-status={}", err);
    }
}

// -----------------------------------------------------------------------------
// Internal Handlers
// -----------------------------------------------------------------------------

async fn handle_default(State(state): State<SharedState>, method: Method, uri: Uri) -> Response {
    let key = (method.to_string(), uri.to_string());

    let spec = {
        let read_guard = state.read().unwrap();
        read_guard.dynamic_endpoints.get(&key).cloned()
    };

    if let Some(spec) = spec {
        return perform_reflection(method, uri, spec).into_response();
    }

    info!("Received default request to {}", uri);
    StatusCode::OK.into_response()
}

async fn handle_capabilities(
    State(state): State<SharedState>,
    Query(params): Query<CapabilitiesQuery>,
) -> Response {
    info!("Received capabilities request");

    let read_guard = state.read().unwrap();
    let mut spec = read_guard.capabilities.clone();

    if params.quiet.as_deref() == Some("true") {
        spec.endpoints = spec
            .endpoints
            .into_iter()
            .map(|ep| Endpoint {
                path: ep.path,
                methods: vec![],
                content_type: String::new(),
                description: String::new(),
            })
            .collect();
    }

    let body = if params.pretty.as_deref() == Some("true") {
        serde_json::to_string_pretty(&spec).unwrap()
    } else {
        serde_json::to_string(&spec).unwrap()
    };

    ([(http::header::CONTENT_TYPE, "application/json")], body).into_response()
}

async fn handle_reflect(method: Method, uri: Uri, body: Bytes) -> Response {
    info!("Received reflection request");

    if tracing::enabled!(tracing::Level::DEBUG) {
        let (size, unit) = to_human_readable_memory_size(body.len() as u64);
        debug!("Body size: {}{}", size, unit);
    }

    let spec: ReflectionSpec = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(e) => {
            warn!("Invalid JSON in request body");
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)).into_response();
        }
    };

    perform_reflection(method, uri, spec).into_response()
}

async fn handle_configure_reflection(State(state): State<SharedState>, body: Bytes) -> Response {
    info!("Received configuration request");

    let spec: ConfigureReflectionSpec = match serde_json::from_slice(&body) {
        Ok(spec) => spec,
        Err(error) => {
            info!("Invalid JSON in request body");
            return (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", error)).into_response();
        }
    };

    let mut write_guard = state.write().unwrap();
    for endpoint in spec.endpoints {
        let key = (endpoint.method, endpoint.url);
        write_guard
            .dynamic_endpoints
            .insert(key, spec.reflection.clone());
    }

    StatusCode::OK.into_response()
}

async fn handle_reset(State(state): State<SharedState>) -> Response {
    info!("Received reset request. Discarding all endpoint configurations now");
    let mut write_guard = state.write().unwrap();
    write_guard.dynamic_endpoints.clear();
    StatusCode::OK.into_response()
}

async fn handle_inspect(method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    info!("Received inspection request");

    let path_str = uri.path();
    let endpoint_suffix = if let Some(idx) = path_str.find("/inspect") {
        let suffix = &path_str[idx + "/inspect".len()..];
        if suffix.is_empty() {
            "/"
        } else {
            suffix
        }
    } else {
        path_str
    };

    let mut header_keys: Vec<_> = headers.keys().map(|k| k.as_str()).collect();
    header_keys.sort();

    let mut headers_log = String::new();
    for key in header_keys {
        for value in headers.get_all(key) {
            if let Ok(v_str) = value.to_str() {
                headers_log.push_str(&format!("{}={} ", key, v_str));
            }
        }
    }

    let (size, unit) = to_human_readable_memory_size(body.len() as u64);

    info!(
        request.protocol = ?uri.scheme(),
        request.verb = ?method,
        request.endpoint = endpoint_suffix,
        request.headers = ?headers_log.trim(),
        request.body.length.value = size,
        request.body.length.unit = unit,
        "Request information"
    );

    if tracing::enabled!(tracing::Level::DEBUG) {
        if let Ok(body_str) = std::str::from_utf8(&body) {
            debug!(request.body.content = body_str);
        }
    }

    StatusCode::OK.into_response()
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn perform_reflection(method: Method, uri: Uri, spec: ReflectionSpec) -> Response {
    info!("Reflecting response for '{}' request to '{}'", method, uri);

    if !spec.log_message.is_empty() {
        info!("{}", spec.log_message);
    }

    let mut response_builder = Response::builder();

    let status_code = if spec.status == 0 { 200 } else { spec.status };
    if !(100..=599).contains(&status_code) {
        let msg = format!("Invalid status code: {}", status_code);
        info!("{}", msg);
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    info!("Reflecting status '{}'", status_code);
    response_builder = response_builder.status(StatusCode::from_u16(status_code).unwrap());

    for (k, v) in &spec.headers {
        info!("Reflecting header '{}':'{}'", k, v);
        if let (Ok(header_name), Ok(header_value)) = (
            axum::http::HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            response_builder = response_builder.header(header_name, header_value);
        }
    }

    let body_content = match decode_body(&spec) {
        Ok(b) => b,
        Err(e) => {
            info!("{}", e);
            return (StatusCode::BAD_REQUEST, e).into_response();
        }
    };

    if body_content.is_empty() {
        info!("Reflecting empty body");
        return response_builder.body(Body::empty()).unwrap();
    }

    let mut log_preview = body_content.clone();
    if log_preview.len() > 200 {
        log_preview.truncate(200);
        log_preview.push_str("...");
    }
    info!("Reflecting body '{}'", log_preview);

    response_builder.body(Body::from(body_content)).unwrap()
}

fn decode_body(spec: &ReflectionSpec) -> Result<String, String> {
    debug!("Decoding body");
    if !spec.body.is_empty() {
        return Ok(spec.body.clone());
    }
    if spec.encoded_body.is_empty() {
        return Ok(String::new());
    }

    let decoded_bytes = BASE64
        .decode(&spec.encoded_body)
        .map_err(|_| "invalid base64 encoding of response body".to_string())?;

    String::from_utf8(decoded_bytes)
        .map_err(|_| "decoded body is not valid utf8".to_string())
}

fn to_human_readable_memory_size(num_bytes: u64) -> (u64, &'static str) {
    let units = ["B", "KB", "MB", "GB"];
    let mut unit_idx = 0;
    let mut size = num_bytes;

    while size > 10000 && unit_idx < units.len() {
        size /= 1000;
        unit_idx += 1;
    }

    (
        size,
        if unit_idx < units.len() {
            units[unit_idx]
        } else {
            "(too big...)"
        },
    )
}
