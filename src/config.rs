//! Configuration — CLI flags, environment variables, config file.

use clap::Parser;
use std::fs;
use std::path::Path;

/// Multigres — Virtual Private Database for PostgreSQL
#[derive(Parser, Debug)]
#[command(name = "multigres", version, about)]
pub struct Cli {
    /// Config file path
    #[arg(long, default_value = "multigres.conf")]
    pub config: String,

    /// Listen port
    #[arg(long, short = 'p')]
    pub port: Option<u16>,

    /// Bind address
    #[arg(long)]
    pub listen_host: Option<String>,

    /// Upstream Postgres host
    #[arg(long)]
    pub upstream_host: Option<String>,

    /// Upstream Postgres port
    #[arg(long)]
    pub upstream_port: Option<u16>,

    /// Tenant separator in username
    #[arg(long)]
    pub separator: Option<String>,

    /// Comma-separated context variable names
    #[arg(long)]
    pub context: Option<String>,

    /// Separator for multiple values in tenant payload
    #[arg(long)]
    pub value_separator: Option<String>,

    /// Comma-separated superuser bypass usernames
    #[arg(long)]
    pub superuser: Option<String>,

    /// Log level
    #[arg(long)]
    pub log_level: Option<String>,

    /// TLS listen port (enables TLS termination)
    #[arg(long)]
    pub tls_port: Option<u16>,

    /// Path to TLS certificate (PEM)
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// Path to TLS private key (PEM)
    #[arg(long)]
    pub tls_key: Option<String>,

    /// Enable TLS to upstream Postgres
    #[arg(long)]
    pub upstream_tls: bool,

    /// Verify upstream TLS certificate (default: true)
    #[arg(long)]
    pub upstream_tls_verify: Option<bool>,

    /// Path to custom CA certificate for upstream TLS
    #[arg(long)]
    pub upstream_tls_ca: Option<String>,

    /// Handshake timeout in seconds
    #[arg(long)]
    pub handshake_timeout: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_port: u16,
    pub listen_host: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub tenant_separator: String,
    pub context_variables: Vec<String>,
    pub value_separator: String,
    pub superuser_bypass: Vec<String>,
    pub log_level: String,
    pub tls_port: Option<u16>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub upstream_tls: bool,
    pub upstream_tls_verify: bool,
    pub upstream_tls_ca: Option<String>,
    pub handshake_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_port: 6432,
            listen_host: "127.0.0.1".into(),
            upstream_host: "127.0.0.1".into(),
            upstream_port: 5432,
            tenant_separator: ".".into(),
            context_variables: vec!["app.current_tenant_id".into()],
            value_separator: ":".into(),
            superuser_bypass: vec!["postgres".into()],
            log_level: "info".into(),
            tls_port: None,
            tls_cert: None,
            tls_key: None,
            upstream_tls: false,
            upstream_tls_verify: true,
            upstream_tls_ca: None,
            handshake_timeout_secs: 30,
        }
    }
}

impl Config {
    /// Load configuration: defaults → config file → env vars → CLI flags.
    pub fn load() -> Self {
        let cli = Cli::parse();
        let mut config = Config::default();

        // 1. Config file
        let config_path = Path::new(&cli.config);
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(config_path) {
                apply_config_file(&mut config, &content);
            }
        }

        // 2. Environment variables
        apply_env(&mut config);

        // 3. CLI flags (highest priority)
        if let Some(v) = cli.port {
            config.listen_port = v;
        }
        if let Some(v) = cli.listen_host {
            config.listen_host = v;
        }
        if let Some(v) = cli.upstream_host {
            config.upstream_host = v;
        }
        if let Some(v) = cli.upstream_port {
            config.upstream_port = v;
        }
        if let Some(v) = cli.separator {
            config.tenant_separator = v;
        }
        if let Some(v) = cli.context {
            config.context_variables = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Some(v) = cli.value_separator {
            config.value_separator = v;
        }
        if let Some(v) = cli.superuser {
            config.superuser_bypass = v.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Some(v) = cli.log_level {
            config.log_level = v;
        }
        if let Some(v) = cli.tls_port {
            config.tls_port = Some(v);
        }
        if let Some(v) = cli.tls_cert {
            config.tls_cert = Some(v);
        }
        if let Some(v) = cli.tls_key {
            config.tls_key = Some(v);
        }
        if cli.upstream_tls {
            config.upstream_tls = true;
        }
        if let Some(v) = cli.upstream_tls_verify {
            config.upstream_tls_verify = v;
        }
        if let Some(v) = cli.upstream_tls_ca {
            config.upstream_tls_ca = Some(v);
        }
        if let Some(v) = cli.handshake_timeout {
            config.handshake_timeout_secs = v;
        }

        config
    }

    /// Validate configuration. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.tls_port.is_some() {
            if self.tls_cert.is_none() || self.tls_key.is_none() {
                return Err("tls_port requires both tls_cert and tls_key".into());
            }
        }
        if self.handshake_timeout_secs == 0 {
            return Err("handshake_timeout must be > 0".into());
        }
        Ok(())
    }
}

fn apply_config_file(config: &mut Config, content: &str) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Some(eq_pos) = trimmed.find('=') else {
            continue;
        };

        let key = trimmed[..eq_pos].trim();
        let mut value = trimmed[eq_pos + 1..].trim().to_string();

        // Strip quotes
        if (value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\''))
        {
            value = value[1..value.len() - 1].to_string();
        }

        match key {
            "port" | "listen_port" => {
                if let Ok(v) = value.parse() {
                    config.listen_port = v;
                }
            }
            "listen_host" | "host" => config.listen_host = value,
            "upstream_host" => config.upstream_host = value,
            "upstream_port" => {
                if let Ok(v) = value.parse() {
                    config.upstream_port = v;
                }
            }
            "tenant_separator" | "separator" => config.tenant_separator = value,
            "context_variables" | "context" => {
                config.context_variables =
                    value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "value_separator" => config.value_separator = value,
            "superuser_bypass" | "superuser" => {
                config.superuser_bypass =
                    value.split(',').map(|s| s.trim().to_string()).collect();
            }
            "log_level" => config.log_level = value,
            "tls_port" => {
                if let Ok(v) = value.parse() {
                    config.tls_port = Some(v);
                }
            }
            "tls_cert" => config.tls_cert = Some(value),
            "tls_key" => config.tls_key = Some(value),
            "upstream_tls" => {
                config.upstream_tls = matches!(value.as_str(), "true" | "1" | "yes");
            }
            "upstream_tls_verify" => {
                config.upstream_tls_verify = !matches!(value.as_str(), "false" | "0" | "no");
            }
            "upstream_tls_ca" => config.upstream_tls_ca = Some(value),
            "handshake_timeout" | "handshake_timeout_secs" => {
                if let Ok(v) = value.parse() {
                    config.handshake_timeout_secs = v;
                }
            }
            _ => {}
        }
    }
}

fn apply_env(config: &mut Config) {
    if let Ok(v) = std::env::var("MULTIGRES_PORT") {
        if let Ok(p) = v.parse() {
            config.listen_port = p;
        }
    }
    if let Ok(v) = std::env::var("MULTIGRES_HOST") {
        config.listen_host = v;
    }
    if let Ok(v) = std::env::var("MULTIGRES_UPSTREAM_HOST") {
        config.upstream_host = v;
    }
    if let Ok(v) = std::env::var("MULTIGRES_UPSTREAM_PORT") {
        if let Ok(p) = v.parse() {
            config.upstream_port = p;
        }
    }
    if let Ok(v) = std::env::var("MULTIGRES_TENANT_SEPARATOR") {
        config.tenant_separator = v;
    }
    if let Ok(v) = std::env::var("MULTIGRES_CONTEXT_VARIABLES") {
        config.context_variables = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Ok(v) = std::env::var("MULTIGRES_VALUE_SEPARATOR") {
        config.value_separator = v;
    }
    if let Ok(v) = std::env::var("MULTIGRES_SUPERUSER_BYPASS") {
        config.superuser_bypass = v.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Ok(v) = std::env::var("MULTIGRES_LOG_LEVEL") {
        config.log_level = v;
    }
    if let Ok(v) = std::env::var("MULTIGRES_TLS_PORT") {
        if let Ok(p) = v.parse() {
            config.tls_port = Some(p);
        }
    }
    if let Ok(v) = std::env::var("MULTIGRES_TLS_CERT") {
        config.tls_cert = Some(v);
    }
    if let Ok(v) = std::env::var("MULTIGRES_TLS_KEY") {
        config.tls_key = Some(v);
    }
    if let Ok(v) = std::env::var("MULTIGRES_UPSTREAM_TLS") {
        config.upstream_tls = matches!(v.as_str(), "true" | "1" | "yes");
    }
    if let Ok(v) = std::env::var("MULTIGRES_UPSTREAM_TLS_VERIFY") {
        config.upstream_tls_verify = !matches!(v.as_str(), "false" | "0" | "no");
    }
    if let Ok(v) = std::env::var("MULTIGRES_UPSTREAM_TLS_CA") {
        config.upstream_tls_ca = Some(v);
    }
    if let Ok(v) = std::env::var("MULTIGRES_HANDSHAKE_TIMEOUT") {
        if let Ok(t) = v.parse() {
            config.handshake_timeout_secs = t;
        }
    }
}
