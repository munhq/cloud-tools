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
