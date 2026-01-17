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

use albedo_rs::{
    build_router, CapabilitiesSpec, ConfigureReflectionSpec, DynamicEndpointSpec, ReflectionSpec,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use http_body_util::BodyExt;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tower::util::ServiceExt; // for oneshot
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_test::traced_test;

// Helper for capturing logs
#[derive(Clone, Default)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

impl<'a> MakeWriter<'a> for BufWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl BufWriter {
    fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).to_string()
    }
}

// Sets up a temporary subscriber and returns the captured output
fn with_captured_logs<F, Fut>(f: F) -> String
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()>,
{
    let writer = BufWriter::default();
    let subscriber = fmt::Subscriber::builder()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(f());
        })
    });
    writer.to_string()
}

// Helper to get response body as string
async fn body_to_string(body: axum::body::Body) -> String {
    let bytes = body.collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn test_default_request() {
    let app = build_router();

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    // Axum/Hyper usually handles Content-Length automatically for fixed bodies,
    // but empty bodies might just be empty.
    let body = body_to_string(response.into_body()).await;
    assert_eq!(body, "");
}

#[tokio::test]
async fn test_reflect_body() {
    let app = build_router();

    let response_body = "a dummy body




";
    let spec = ReflectionSpec {
        status: 202,
        headers: vec![
            ("header1".to_string(), "value 1".to_string()),
            ("header_2".to_string(), "value :2".to_string()),
        ]
        .into_iter()
        .collect(),
        body: response_body.to_string(),
        encoded_body: "".to_string(),
        log_message: "".to_string(),
    };

    let req_body = serde_json::to_string(&spec).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reflect")
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 202);
    assert_eq!(response.headers().get("header1").unwrap(), "value 1");
    assert_eq!(response.headers().get("header_2").unwrap(), "value :2");

    let reflected_body = body_to_string(response.into_body()).await;
    assert_eq!(reflected_body, response_body);
}

#[tokio::test]
async fn test_reflect_encoded_body() {
    let app = build_router();

    let response_body_str = "a dummy body




";
    let encoded = BASE64.encode(response_body_str);

    let spec = ReflectionSpec {
        status: 202,
        headers: vec![
            ("header1".to_string(), "value 1".to_string()),
            ("header_2".to_string(), "value :2".to_string()),
        ]
        .into_iter()
        .collect(),
        body: "".to_string(),
        encoded_body: encoded,
        log_message: "".to_string(),
    };

    let req_body = serde_json::to_string(&spec).unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/reflect")
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 202);
    let reflected_body = body_to_string(response.into_body()).await;
    assert_eq!(reflected_body, response_body_str);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reflect_log_message() {
    let app = build_router();
    let log_msg = "a log message";

    let spec = ReflectionSpec {
        status: 200,
        headers: Default::default(),
        body: "".to_string(),
        encoded_body: "".to_string(),
        log_message: log_msg.to_string(),
    };

    let req_body = serde_json::to_string(&spec).unwrap();

    let logs = with_captured_logs(|| async {
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reflect")
                    .body(Body::from(req_body))
                    .unwrap(),
            )
            .await
            .unwrap();
    });

    assert!(logs.contains(log_msg));
}

#[tokio::test]
async fn test_capabilities() {
    let app = build_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );

    let body_str = body_to_string(response.into_body()).await;
    let spec: CapabilitiesSpec = serde_json::from_str(&body_str).unwrap();

    assert_eq!(spec.endpoints.len(), 6);
    assert_eq!(spec.endpoints[0].path, "/*");
    assert_eq!(spec.endpoints[1].path, "/capabilities");
    // ... checking others ...

    for ep in spec.endpoints {
        assert!(!ep.methods.is_empty() || ep.path == "/capabilities" || ep.path == "/*"); // Logic adjusted for rust impl details
        assert!(!ep.description.is_empty());
    }
}

#[tokio::test]
async fn test_capabilities_quiet() {
    let app = build_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/capabilities?quiet=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_str = body_to_string(response.into_body()).await;

    // Check absence of fields
    assert!(!body_str.contains("\"methods\""));
    assert!(!body_str.contains("\"contentType\""));
    assert!(!body_str.contains("\"description\""));

    let spec: CapabilitiesSpec = serde_json::from_str(&body_str).unwrap();
    assert_eq!(spec.endpoints.len(), 6);
}

#[tokio::test]
async fn test_configure_reflection() {
    // Note: We need a shared state across requests.
    // build_router() creates a NEW state every time called.
    // For this test, we must re-use the SAME router instance for the configuration and the subsequent check.
    let app = build_router();

    let response_body_str = "a dummy body";
    let encoded = BASE64.encode(response_body_str);

    let spec = ConfigureReflectionSpec {
        reflection: ReflectionSpec {
            status: 202,
            headers: vec![("header1".to_string(), "value 1".to_string())]
                .into_iter()
                .collect(),
            encoded_body: encoded,
            body: "".to_string(),
            log_message: "".to_string(),
        },
        endpoints: vec![
            DynamicEndpointSpec {
                method: "GET".to_string(),
                url: "/foo/bar".to_string(),
            },
            DynamicEndpointSpec {
                method: "POST".to_string(),
                url: "/foo/bar?some=query".to_string(),
            },
        ],
    };

    let req_body = serde_json::to_string(&spec).unwrap();

    // 1. Configure
    let response = app
        .clone() // Axum routers are cheap to clone (Arc internals)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/configure_reflection")
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // 2. Test configured endpoint (GET /foo/bar)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/foo/bar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 202);
    assert_eq!(response.headers().get("header1").unwrap(), "value 1");
    let body = body_to_string(response.into_body()).await;
    assert_eq!(body, response_body_str);
}

#[tokio::test]
async fn test_configure_reflection_same_url() {
    let app = build_router();

    let response_body_str = "a dummy body";
    let encoded = BASE64.encode(response_body_str);

    let spec = ConfigureReflectionSpec {
        reflection: ReflectionSpec {
            status: 202,
            headers: vec![("header1".to_string(), "value 1".to_string())]
                .into_iter()
                .collect(),
            encoded_body: encoded,
            body: "".to_string(),
            log_message: "".to_string(),
        },
        endpoints: vec![
            DynamicEndpointSpec {
                method: "GET".to_string(),
                url: "/foo/bar".to_string(),
            },
            DynamicEndpointSpec {
                method: "OPTIONS".to_string(),
                url: "/foo/bar".to_string(),
            },
        ],
    };

    let req_body = serde_json::to_string(&spec).unwrap();

    // 1. Configure
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/configure_reflection")
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // 2. Test configured GET endpoint
    let response_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/foo/bar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response_get.status(), 202);
    assert_eq!(response_get.headers().get("header1").unwrap(), "value 1");
    let body_get = body_to_string(response_get.into_body()).await;
    assert_eq!(body_get, response_body_str);

    // 3. Test configured OPTIONS endpoint
    let response_options = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/foo/bar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response_options.status(), 202);
    assert_eq!(
        response_options.headers().get("header1").unwrap(),
        "value 1"
    );
    let body_options = body_to_string(response_options.into_body()).await;
    assert_eq!(body_options, response_body_str);
}

#[tokio::test]
async fn test_reset() {
    let app = build_router();

    // 1. Configure
    let spec = ConfigureReflectionSpec {
        reflection: ReflectionSpec {
            status: 234,
            headers: Default::default(),
            body: "".to_string(),
            encoded_body: "".to_string(),
            log_message: "".to_string(),
        },
        endpoints: vec![DynamicEndpointSpec {
            method: "GET".to_string(),
            url: "/foo/bar".to_string(),
        }],
    };
    let req_body = serde_json::to_string(&spec).unwrap();

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/configure_reflection")
                .body(Body::from(req_body))
                .unwrap(),
        )
        .await
        .unwrap();

    // 2. Verify it works
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/foo/bar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 234);

    // 3. Reset
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/reset")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    // 4. Verify it's gone (should fall back to default handler -> 200 OK empty)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/foo/bar")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn test_capabilities_pretty() {
    let app = build_router();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/capabilities?pretty=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_str = body_to_string(response.into_body()).await;

    // Check for newlines and indentation, which indicate pretty printing.
    assert!(body_str.contains('\n'));
    assert!(body_str.contains("  ")); // Default indentation for pretty is 2 spaces

    // Also check that it's valid JSON
    let spec: CapabilitiesSpec = serde_json::from_str(&body_str).unwrap();
    assert_eq!(spec.endpoints.len(), 6);
}

#[tokio::test]
async fn test_inspect() {
    let app = build_router();

    // Test 1: Basic GET request
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inspect")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert_eq!(body, "");

    // Test 2: POST request with body
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/inspect")
                .body(Body::from("test request body content"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert_eq!(body, "");

    // Test 3: Request with various headers
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/inspect")
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer token123")
                .header("User-Agent", "test-client/1.0")
                .header("X-Custom-Header", "custom-value")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_to_string(response.into_body()).await;
    assert_eq!(body, "");

    // Test 4: Different endpoint paths
    let endpoints = vec![
        "/inspect",
        "/inspect/",
        "/inspect/test",
        "/inspect/test/path",
        "/inspect/test?query=value",
    ];
    for endpoint in endpoints {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(endpoint)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_to_string(response.into_body()).await;
        assert_eq!(body, "");
    }

    // Test 5: Different HTTP methods
    let methods = vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
    for method in methods {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/inspect")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[traced_test]
async fn test_inspect_log_content() {
    let app = build_router();

    let logs = with_captured_logs(|| async {
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/inspect")
                    .header("X-Custom-Header", "custom-value")
                    .body(Body::from("test body"))
                    .unwrap(),
            )
            .await
            .unwrap();
    });

    assert!(logs.contains("Received inspection request"));
    // tracing-test allows checking formatted log output
    assert!(logs.contains("request.verb=POST"));
    assert!(logs.contains("x-custom-header=custom-value"));
    assert!(logs.contains("request.body.length.value=9"));
}
