use anyhow::Result;
use cloud_tools::tools::CloudTools;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

mod http_server;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let mode = std::env::var("CLOUD_TOOLS_MODE").unwrap_or_else(|_| "mcp".to_string());

    match mode.as_str() {
        "http" => {
            let port: u16 = std::env::var("CLOUD_TOOLS_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(9091);
            http_server::serve(port).await?;
        }
        _ => {
            tracing::info!("cloud-tools MCP server starting on stdio");
            CloudTools::new()
                .serve(rmcp::transport::stdio())
                .await
                .map_err(|e| anyhow::anyhow!("Server init failed: {e}"))?
                .waiting()
                .await
                .map_err(|e| anyhow::anyhow!("Server error: {e}"))?;
        }
    }

    Ok(())
}
