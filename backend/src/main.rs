//! Example JWT authorization/authentication.
//!
//! Run with
//!
//! ```not_rust
//! JWT_SECRET=secret cargo run -p example-jwt
//! ```

use std::net::SocketAddr;

use axum::{http::Method, routing::get, Router};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::{DefaultMakeSpan, TraceLayer},
};

mod api;
mod logging;
use crate::api::ws_handler;
use crate::logging::init_logging;

#[tokio::main]
async fn main() {
    let _sg = init_logging();

    // CORS Setup
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(Any);

    // All routes placed behind /api
    let api_routes = Router::new().route("/ws", get(ws_handler));

    // Main application router
    let app = Router::new().nest("/api", api_routes).layer(cors).layer(
        TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::default().include_headers(true)),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:9005")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
