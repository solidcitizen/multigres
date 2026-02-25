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

        config
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
}
