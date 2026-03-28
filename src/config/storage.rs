use std::fs;
use std::path::PathBuf;

use crate::audit::log::append_server_event;
use crate::config::paths::{config_dir, legacy_config_dir};
use crate::config::server::{AuthMethod, Server};
use crate::security::secrets::{clear_server_password, store_server_password};

const SERVERS_FILE_NAME: &str = "servers.json";

fn app_config_dir() -> PathBuf {
    config_dir()
}

fn legacy_servers_path() -> PathBuf {
    legacy_config_dir().join(SERVERS_FILE_NAME)
}

pub fn config_path() -> PathBuf {
    app_config_dir().join(SERVERS_FILE_NAME)
}

pub fn load_servers() -> Vec<Server> {
    let primary = config_path();
    let legacy = legacy_servers_path();
    let (path, data) = match fs::read_to_string(&primary) {
        Ok(data) => (primary, data),
        Err(_) => match fs::read_to_string(&legacy) {
            Ok(data) => (legacy, data),
            Err(_) => return vec![],
        },
    };

    let mut servers = match serde_json::from_str::<Vec<Server>>(&data) {
        Ok(servers) => servers,
        Err(error) => {
            eprintln!("解析服务器配置失败 {:?}: {error}", path);
            return vec![];
        }
    };

    let mut migrated_plaintext_passwords = false;
    for server in &mut servers {
        *server = server.normalized();

        if server.auth_method == AuthMethod::Password && server.password.is_some() {
            let password = server.password.clone().unwrap_or_default();
            match store_server_password(server, &password) {
                Ok(()) => {
                    server.password = None;
                    server.password_in_keyring = true;
                    migrated_plaintext_passwords = true;
                    append_server_event(server, "凭据迁移", "已将明文密码迁移到安全凭据存储。");
                }
                Err(error) => {
                    eprintln!("{} 迁移凭据失败: {error:#}", server.endpoint());
                }
            }
        }
    }

    servers.sort_by(|left, right| {
        left.group_name()
            .to_lowercase()
            .cmp(&right.group_name().to_lowercase())
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.host.to_lowercase().cmp(&right.host.to_lowercase()))
    });

    if migrated_plaintext_passwords || path != config_path() {
        save_servers(&servers);
    }

    servers
}

pub fn save_servers(servers: &[Server]) {
    let mut normalized_servers: Vec<Server> = Vec::with_capacity(servers.len());

    for server in servers.iter().map(Server::normalized) {
        let mut normalized = server;

        match normalized.auth_method {
            AuthMethod::Password => {
                if let Some(password) = normalized.password.clone() {
                    match store_server_password(&normalized, &password) {
                        Ok(()) => {
                            normalized.password = None;
                            normalized.password_in_keyring = true;
                            append_server_event(
                                &normalized,
                                "凭据保存",
                                "已将密码写入安全凭据存储。",
                            );
                        }
                        Err(error) => {
                            eprintln!("{} 写入安全凭据失败: {error:#}", normalized.endpoint());
                        }
                    }
                }
            }
            AuthMethod::PrivateKey => {
                if let Err(error) = clear_server_password(&normalized) {
                    eprintln!("{} 清理安全凭据失败: {error:#}", normalized.endpoint());
                }
                normalized.password = None;
                normalized.password_in_keyring = false;
            }
        }

        if normalized.auth_method == AuthMethod::Password
            && normalized.password.is_none()
            && !normalized.password_in_keyring
        {
            let _ = clear_server_password(&normalized);
        }

        normalized_servers.push(normalized);
    }

    normalized_servers.sort_by(|left, right| {
        left.group_name()
            .to_lowercase()
            .cmp(&right.group_name().to_lowercase())
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.host.to_lowercase().cmp(&right.host.to_lowercase()))
    });

    if let Err(error) = fs::create_dir_all(app_config_dir()) {
        eprintln!("创建配置目录失败: {error}");
        return;
    }

    let data = match serde_json::to_string_pretty(&normalized_servers) {
        Ok(data) => data,
        Err(error) => {
            eprintln!("序列化服务器配置失败: {error}");
            return;
        }
    };

    if let Err(error) = fs::write(config_path(), data) {
        eprintln!("保存服务器配置失败: {error}");
    }
}
