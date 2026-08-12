// Several cloud API wrappers legitimately take more than seven parameters:
// credentials, region, filters and pagination cursors all travel together.
#![allow(clippy::too_many_arguments)]
// Matching on Ok(..) with an explicit commented catch-all documents *why* the
// error path is ignored. `if let` would drop that comment.
#![allow(clippy::single_match)]

pub mod analyzers;
pub mod clouds;
pub mod setup;
pub mod types;

/// MCP server tools — only available with the `mcp` feature (requires rmcp).
#[cfg(feature = "mcp")]
pub mod tools;

/// HTTP server (axum) — only available with the `http` feature.
#[cfg(feature = "http")]
pub mod http_server;
