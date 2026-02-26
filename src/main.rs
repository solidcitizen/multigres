mod admin;
mod auth;
mod config;
mod connection;
mod metrics;
mod pool;
mod protocol;
mod proxy;
mod resolver;
mod stream;
mod tenant;
mod tls;

use tracing_subscriber::EnvFilter;

const BANNER: &str = r#"
  ╔══════════════════════════════════════════════════╗
  ║                  P G V P D  v0.6                 ║
  ║      Virtual Private Database for PostgreSQL     ║
  ║                    [ Rust ]                      ║
  ╚══════════════════════════════════════════════════╝
"#;

#[tokio::main]
async fn main() {
    let config = config::Config::load();

    // Set up tracing with the configured log level
    let filter = EnvFilter::try_new(&config.log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .init();

    eprintln!("{BANNER}");

    if let Err(e) = proxy::run(config).await {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
