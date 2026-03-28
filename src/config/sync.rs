use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use dirs::{config_dir, home_dir};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::preferences::ThemePreset;
use crate::config::server::Server;
use crate::history::history::{CommandHistory, ConnectionHistory, Script, ShortcutCommand};

const APP_DIR_NAME: &str = "rustssh_manager";
const SYNC_DIR_NAME: &str = "sync_accounts";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    Existing,
    Created,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct SyncSnapshot {
    // Treat the snapshot as a whole workspace export so sync/pull/import all share one format.
    pub theme_preset: ThemePreset,
    pub servers: Vec<Server>,
    pub connection_history: Vec<ConnectionHistory>,
    pub command_history: Vec<CommandHistory>,
    pub shortcuts: Vec<ShortcutCommand>,
    pub scripts: Vec<Script>,
    pub synced_at: u64,
}

impl Default for SyncSnapshot {
    fn default() -> Self {
        Self {
            theme_preset: ThemePreset::PeachBlossom,
            servers: Vec::new(),
            connection_history: Vec::new(),
            command_history: Vec::new(),
            shortcuts: Vec::new(),
            scripts: Vec::new(),
            synced_at: 0,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
struct SyncAccount {
    username: String,
    password_hash: String,
    last_sync_at: u64,
    snapshot: SyncSnapshot,
}

impl SyncSnapshot {
    pub fn with_timestamp(mut self) -> Self {
        self.synced_at = unix_timestamp();
        self
    }
}

pub fn authenticate_or_create_account(
    username: &str,
    password: &str,
    initial_snapshot: SyncSnapshot,
) -> Result<LoginOutcome> {
    let username = normalize_username(username);
    let password = password.trim();
    if username.is_empty() {
        bail!("请输入同步账号名。");
    }
    if password.is_empty() {
        bail!("请输入同步密码。");
    }

    let expected_hash = password_hash(&username, password);
    match load_account(&username)? {
        Some(account) => {
            // Existing accounts only need local password verification before we expose sync actions.
            if account.password_hash != expected_hash {
                bail!("同步密码不正确。");
            }
            Ok(LoginOutcome::Existing)
        }
        None => {
            // First sign-in bootstraps the account from the current local workspace state.
            let account = SyncAccount {
                username: username.clone(),
                password_hash: expected_hash,
                last_sync_at: unix_timestamp(),
                snapshot: initial_snapshot.with_timestamp(),
            };
            save_account(&account)?;
            Ok(LoginOutcome::Created)
        }
    }
}

pub fn pull_snapshot(username: &str) -> Result<Option<SyncSnapshot>> {
    Ok(load_account(&normalize_username(username))?.map(|account| account.snapshot))
}

pub fn push_snapshot(username: &str, snapshot: SyncSnapshot) -> Result<()> {
    let username = normalize_username(username);
    let mut account =
        load_account(&username)?.ok_or_else(|| anyhow!("同步账号不存在，请先登录。"))?;
    account.last_sync_at = unix_timestamp();
    account.snapshot = snapshot.with_timestamp();
    save_account(&account)
}

fn load_account(username: &str) -> Result<Option<SyncAccount>> {
    let path = account_path(username);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        // "No account yet" is a valid branch because sign-in doubles as account creation.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("读取同步账号失败 {:?}", path));
        }
    };

    let account = serde_json::from_str::<SyncAccount>(&data)
        .with_context(|| format!("解析同步账号失败 {:?}", path))?;
    Ok(Some(account))
}

fn save_account(account: &SyncAccount) -> Result<()> {
    let path = account_path(&account.username);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("创建同步目录失败 {:?}", parent))?;
    }

    let payload = serde_json::to_string_pretty(account).context("序列化同步账号失败")?;
    fs::write(&path, payload).with_context(|| format!("写入同步账号失败 {:?}", path))
}

fn account_path(username: &str) -> PathBuf {
    // Usernames become filenames, so we normalize them into a safe cross-platform slug first.
    app_config_dir()
        .join(SYNC_DIR_NAME)
        .join(format!("{}.json", slugify(username)))
}

fn app_config_dir() -> PathBuf {
    config_dir()
        .or_else(home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR_NAME)
}

fn normalize_username(username: &str) -> String {
    username.trim().to_lowercase()
}

fn slugify(username: &str) -> String {
    let mut slug = String::new();
    for ch in username.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            slug.push(ch);
        } else {
            slug.push('_');
        }
    }

    if slug.is_empty() {
        "account".to_string()
    } else {
        slug
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn password_hash(username: &str, password: &str) -> String {
    // A simple salted local hash is enough here because this feature stores accounts on disk,
    // not in a remote multi-tenant service.
    let mut hasher = Sha256::new();
    hasher.update(b"rustssh_manager_sync_v1:");
    hasher.update(username.as_bytes());
    hasher.update(b":");
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}
