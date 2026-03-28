use serde::{Deserialize, Serialize};

pub const DEFAULT_GROUP_NAME: &str = "默认分组";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    #[default]
    Password,
    PrivateKey,
}

impl AuthMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::Password => "密码",
            Self::PrivateKey => "密钥",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ConnectionPolicy {
    pub connect_timeout_secs: u64,
    pub keepalive_interval_secs: u64,
    pub keepalive_max_misses: usize,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: u32,
    pub reconnect_backoff_secs: u64,
}

impl Default for ConnectionPolicy {
    fn default() -> Self {
        Self {
            connect_timeout_secs: 10,
            keepalive_interval_secs: 15,
            keepalive_max_misses: 4,
            auto_reconnect: true,
            max_reconnect_attempts: 3,
            reconnect_backoff_secs: 5,
        }
    }
}

impl ConnectionPolicy {
    pub fn normalized(&self) -> Self {
        Self {
            connect_timeout_secs: self.connect_timeout_secs.clamp(3, 120),
            keepalive_interval_secs: self.keepalive_interval_secs.clamp(5, 300),
            keepalive_max_misses: self.keepalive_max_misses.clamp(1, 20),
            auto_reconnect: self.auto_reconnect,
            max_reconnect_attempts: self.max_reconnect_attempts.min(20),
            reconnect_backoff_secs: self.reconnect_backoff_secs.clamp(1, 300),
        }
    }

    pub fn summary(&self) -> String {
        if self.auto_reconnect {
            format!(
                "自动重连：最多 {} 次 / 退避 {} 秒 / 超时 {} 秒",
                self.max_reconnect_attempts, self.reconnect_backoff_secs, self.connect_timeout_secs
            )
        } else {
            format!("自动重连：关闭 / 超时 {} 秒", self.connect_timeout_secs)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Server {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(skip_serializing)]
    pub password: Option<String>,
    pub group: String,
    pub auth_method: AuthMethod,
    pub private_key_path: Option<String>,
    pub password_in_keyring: bool,
    pub connection_policy: ConnectionPolicy,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: String::new(),
            port: 22,
            user: String::new(),
            password: None,
            group: DEFAULT_GROUP_NAME.to_string(),
            auth_method: AuthMethod::Password,
            private_key_path: None,
            password_in_keyring: false,
            connection_policy: ConnectionPolicy::default(),
        }
    }
}

impl Server {
    pub fn endpoint(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }

    pub fn normalized(&self) -> Self {
        let mut server = self.clone();
        server.name = server.name.trim().to_string();
        server.host = server.host.trim().to_string();
        server.user = server.user.trim().to_string();
        server.group = {
            let group = server.group.trim();
            if group.is_empty() {
                DEFAULT_GROUP_NAME.to_string()
            } else {
                group.to_string()
            }
        };
        server.password = server
            .password
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        server.private_key_path = server
            .private_key_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        server.password_in_keyring = server.password_in_keyring || server.password.is_some();
        if server.auth_method != AuthMethod::Password {
            server.password = None;
            server.password_in_keyring = false;
        }
        server.connection_policy = server.connection_policy.normalized();
        if server.port == 0 {
            server.port = 22;
        }
        if server.name.is_empty() {
            server.name = format!("{}@{}", server.user, server.host);
        }
        server
    }

    pub fn matches_query(&self, query: &str) -> bool {
        let query = query.trim().to_lowercase();
        if query.is_empty() {
            return true;
        }

        [
            self.name.as_str(),
            self.host.as_str(),
            self.user.as_str(),
            self.group_name(),
            self.private_key_path.as_deref().unwrap_or_default(),
        ]
        .into_iter()
        .any(|field| field.to_lowercase().contains(&query))
    }

    pub fn group_name(&self) -> &str {
        if self.group.trim().is_empty() || self.group.eq_ignore_ascii_case("default") {
            DEFAULT_GROUP_NAME
        } else {
            self.group.as_str()
        }
    }

    pub fn server_key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.user.to_lowercase(),
            self.host.to_lowercase(),
            self.port
        )
    }

    pub fn keyring_account(&self) -> String {
        format!("server:{}", self.server_key())
    }
}
