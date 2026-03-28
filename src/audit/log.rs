use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use chrono::Utc;
use dirs::{data_local_dir, home_dir};
use serde::Serialize;

use crate::config::server::Server;

const APP_DIR_NAME: &str = "rustssh_manager";
const AUDIT_LOG_FILE: &str = "audit.log";

static AUDIT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Serialize)]
struct AuditRecord<'a> {
    timestamp: String,
    event_type: &'a str,
    server_name: &'a str,
    host: &'a str,
    port: u16,
    user: &'a str,
    detail: &'a str,
}

pub fn append_server_event(server: &Server, event_type: &str, detail: &str) {
    append_record(AuditRecord {
        timestamp: Utc::now().to_rfc3339(),
        event_type,
        server_name: &server.name,
        host: &server.host,
        port: server.port,
        user: &server.user,
        detail,
    });
}

pub fn append_command_event(server: &Server, command: &str) {
    let detail = format!("命令预览={}", summarize_command(command));
    append_server_event(server, "命令下发", &detail);
}

fn append_record(record: AuditRecord<'_>) {
    let _guard = AUDIT_LOCK.lock().unwrap();

    let path = audit_log_path();
    if let Some(parent) = path.parent() {
        if let Err(error) = create_dir_all(parent) {
            eprintln!("创建审计日志目录失败: {error}");
            return;
        }
    }

    let payload = match serde_json::to_string(&record) {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!("序列化审计记录失败: {error}");
            return;
        }
    };

    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            let _ = writeln!(file, "{payload}");
        }
        Err(error) => {
            eprintln!("写入审计日志失败 {:?}: {error}", path);
        }
    }
}

pub fn audit_log_path() -> PathBuf {
    data_local_dir()
        .or_else(home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR_NAME)
        .join(AUDIT_LOG_FILE)
}

fn summarize_command(command: &str) -> String {
    let mut cleaned = command.trim().replace('\n', " ");
    if cleaned.len() > 160 {
        cleaned.truncate(160);
        cleaned.push_str("...");
    }
    cleaned
}
