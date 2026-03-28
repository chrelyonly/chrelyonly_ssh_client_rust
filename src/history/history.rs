#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use dirs::{data_local_dir, home_dir};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::config::server::Server;

const APP_DIR_NAME: &str = "rustssh_manager";
const CONNECTION_HISTORY_FILE: &str = "connection_history.json";
const COMMAND_HISTORY_FILE: &str = "command_history.json";
const SHORTCUTS_FILE: &str = "shortcuts.json";
const SCRIPTS_FILE: &str = "scripts.json";

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct ConnectionHistory {
    pub server_name: String,
    pub server_group: String,
    pub server_key: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct CommandHistory {
    pub command: String,
    pub host: String,
    pub timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct ShortcutCommand {
    pub name: String,
    pub command: String,
    pub description: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct Script {
    pub name: String,
    pub content: String,
    pub description: String,
    pub created_at: u64,
    pub updated_at: u64,
}

impl ConnectionHistory {
    pub fn new(
        server_name: String,
        server_group: String,
        server_key: String,
        host: String,
        port: u16,
        user: String,
    ) -> Self {
        Self {
            server_name,
            server_group,
            server_key,
            host,
            port,
            user,
            timestamp: unix_timestamp(),
        }
    }

    pub fn from_server(server: &Server) -> Self {
        Self::new(
            server.name.clone(),
            server.group_name().to_string(),
            server.server_key(),
            server.host.clone(),
            server.port,
            server.user.clone(),
        )
    }

    pub fn endpoint(&self) -> String {
        format!("{}@{}:{}", self.user, self.host, self.port)
    }
}

impl CommandHistory {
    pub fn new(command: String, host: String) -> Self {
        Self {
            command,
            host,
            timestamp: unix_timestamp(),
        }
    }
}

impl ShortcutCommand {
    pub fn new(name: String, command: String, description: String) -> Self {
        Self {
            name,
            command,
            description,
        }
    }
}

fn app_data_dir() -> PathBuf {
    data_local_dir()
        .or_else(home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR_NAME)
}

fn connection_history_path() -> PathBuf {
    app_data_dir().join(CONNECTION_HISTORY_FILE)
}

fn command_history_path() -> PathBuf {
    app_data_dir().join(COMMAND_HISTORY_FILE)
}

pub fn shortcuts_path() -> PathBuf {
    app_data_dir().join(SHORTCUTS_FILE)
}

pub fn scripts_path() -> PathBuf {
    app_data_dir().join(SCRIPTS_FILE)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_json_vec<T>(path: &Path) -> Vec<T>
where
    T: DeserializeOwned,
{
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(_) => return vec![],
    };

    match serde_json::from_str::<Vec<T>>(&data) {
        Ok(items) => items,
        Err(error) => {
            eprintln!("解析历史文件失败 {:?}: {error}", path);
            vec![]
        }
    }
}

fn save_json_vec<T>(path: &Path, data: &[T])
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            eprintln!("创建历史目录失败: {error}");
            return;
        }
    }

    let payload = match serde_json::to_string_pretty(data) {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!("序列化历史数据失败: {error}");
            return;
        }
    };

    if let Err(error) = fs::write(path, payload) {
        eprintln!("写入历史文件失败 {:?}: {error}", path);
    }
}

pub fn load_connection_history() -> Vec<ConnectionHistory> {
    load_json_vec(&connection_history_path())
}

pub fn save_connection_history(history: &[ConnectionHistory]) {
    save_json_vec(&connection_history_path(), history);
}

pub fn add_connection_history(
    server_name: &str,
    server_group: &str,
    host: &str,
    port: u16,
    user: &str,
) {
    let mut history = load_connection_history();
    history.insert(
        0,
        ConnectionHistory::new(
            server_name.to_string(),
            server_group.to_string(),
            format!("{}|{}|{}", user.to_lowercase(), host.to_lowercase(), port),
            host.to_string(),
            port,
            user.to_string(),
        ),
    );
    history.truncate(100);
    save_connection_history(&history);
}

pub fn recent_connections(limit: usize) -> Vec<ConnectionHistory> {
    let mut history = load_connection_history();
    history.truncate(limit);
    history
}

pub fn load_command_history() -> Vec<CommandHistory> {
    load_json_vec(&command_history_path())
}

pub fn save_command_history(history: &[CommandHistory]) {
    save_json_vec(&command_history_path(), history);
}

pub fn add_command_history(command: &str, host: &str) {
    let mut history = load_command_history();
    history.insert(
        0,
        CommandHistory::new(command.to_string(), host.to_string()),
    );
    history.truncate(200);
    save_command_history(&history);
}

pub fn recent_commands_for_host(host: &str, limit: usize) -> Vec<CommandHistory> {
    load_command_history()
        .into_iter()
        .filter(|item| item.host == host)
        .take(limit)
        .collect()
}

pub fn load_shortcuts() -> Vec<ShortcutCommand> {
    load_json_vec(&shortcuts_path())
}

pub fn save_shortcuts(shortcuts: &[ShortcutCommand]) {
    save_json_vec(&shortcuts_path(), shortcuts);
}

pub fn add_shortcut(name: &str, command: &str, description: &str) {
    let mut shortcuts = load_shortcuts();
    shortcuts.push(ShortcutCommand::new(
        name.to_string(),
        command.to_string(),
        description.to_string(),
    ));
    save_shortcuts(&shortcuts);
}

pub fn remove_shortcut(name: &str) {
    let mut shortcuts = load_shortcuts();
    shortcuts.retain(|shortcut| shortcut.name != name);
    save_shortcuts(&shortcuts);
}

pub fn load_scripts() -> Vec<Script> {
    load_json_vec(&scripts_path())
}

pub fn save_scripts(scripts: &[Script]) {
    save_json_vec(&scripts_path(), scripts);
}

pub fn add_script(name: &str, content: &str, description: &str) {
    let mut scripts = load_scripts();
    let now = unix_timestamp();
    scripts.push(Script {
        name: name.to_string(),
        content: content.to_string(),
        description: description.to_string(),
        created_at: now,
        updated_at: now,
    });
    save_scripts(&scripts);
}

pub fn update_script(name: &str, content: &str, description: &str) {
    let mut scripts = load_scripts();
    let now = unix_timestamp();

    if let Some(script) = scripts.iter_mut().find(|script| script.name == name) {
        script.content = content.to_string();
        script.description = description.to_string();
        script.updated_at = now;
        save_scripts(&scripts);
    }
}

pub fn remove_script(name: &str) {
    let mut scripts = load_scripts();
    scripts.retain(|script| script.name != name);
    save_scripts(&scripts);
}
