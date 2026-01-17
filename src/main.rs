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

use axum::{body::Body, http::Request, middleware, response::Response};
use tracing::info;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    async fn my_middleware(req: Request<Body>, next: middleware::Next) -> Response {
        info!("Custom middleware: processing request");
        next.run(req).await
    }

    let app = albedo_rs::build_router().layer(middleware::from_fn(my_middleware));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    info!("Listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
