use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use russh::Disconnect;
use russh::client::{self, Config};
use russh_keys::load_secret_key;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::timeout;

use crate::config::server::{AuthMethod, Server};
use crate::security::secrets::load_server_password;
use crate::ssh::client::SSHClient;

#[derive(Clone, Debug)]
pub struct RemoteFileEntry {
    pub name: String,
    pub full_path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub permissions: String,
    pub modified_at: Option<u64>,
}

pub async fn list_dir(
    server: Server,
    path: impl Into<String>,
) -> Result<(String, Vec<RemoteFileEntry>)> {
    let server = server.normalized();
    let requested_path = normalize_remote_path(path.into());
    let (mut session, sftp) = connect_sftp(&server).await?;

    let canonical = sftp
        .canonicalize(&requested_path)
        .await
        .with_context(|| format!("解析远端路径失败：{requested_path}"))?;
    let read_dir = sftp
        .read_dir(&canonical)
        .await
        .with_context(|| format!("读取远端目录失败：{canonical}"))?;

    let mut entries: Vec<RemoteFileEntry> = read_dir
        .map(|entry| {
            let metadata = entry.metadata();
            RemoteFileEntry {
                name: entry.file_name(),
                full_path: join_remote_path(&canonical, &entry.file_name()),
                is_dir: metadata.is_dir(),
                is_symlink: metadata.is_symlink(),
                size: metadata.len(),
                permissions: metadata.permissions().to_string(),
                modified_at: metadata.mtime.map(u64::from),
            }
        })
        .collect();

    entries.sort_by(|left, right| {
        right
            .is_dir
            .cmp(&left.is_dir)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });

    shutdown_sftp(&mut session, &sftp).await;
    Ok((canonical, entries))
}

pub async fn download_file(
    server: Server,
    remote_path: impl Into<String>,
    local_path: PathBuf,
) -> Result<PathBuf> {
    let server = server.normalized();
    let remote_path = normalize_remote_path(remote_path.into());
    let (mut session, sftp) = connect_sftp(&server).await?;

    let bytes = sftp
        .read(&remote_path)
        .await
        .with_context(|| format!("读取远端文件失败：{remote_path}"))?;

    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("创建本地目录失败：{}", parent.display()))?;
    }

    fs::write(&local_path, bytes)
        .await
        .with_context(|| format!("写入本地文件失败：{}", local_path.display()))?;

    shutdown_sftp(&mut session, &sftp).await;
    Ok(local_path)
}

pub async fn upload_file(
    server: Server,
    local_path: PathBuf,
    remote_path: impl Into<String>,
) -> Result<String> {
    let server = server.normalized();
    let remote_path = normalize_remote_path(remote_path.into());
    let (mut session, sftp) = connect_sftp(&server).await?;

    let bytes = fs::read(&local_path)
        .await
        .with_context(|| format!("读取本地文件失败：{}", local_path.display()))?;

    let mut remote_file = sftp
        .open_with_flags(
            &remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
        )
        .await
        .with_context(|| format!("打开远端文件失败：{remote_path}"))?;
    remote_file
        .write_all(&bytes)
        .await
        .with_context(|| format!("写入远端文件失败：{remote_path}"))?;
    let _ = remote_file.shutdown().await;

    shutdown_sftp(&mut session, &sftp).await;
    Ok(remote_path)
}

pub async fn create_dir(server: Server, path: impl Into<String>) -> Result<String> {
    let server = server.normalized();
    let path = normalize_remote_path(path.into());
    let (mut session, sftp) = connect_sftp(&server).await?;

    sftp.create_dir(&path)
        .await
        .with_context(|| format!("创建远端目录失败：{path}"))?;

    shutdown_sftp(&mut session, &sftp).await;
    Ok(path)
}

pub async fn remove_path(server: Server, path: impl Into<String>, is_dir: bool) -> Result<String> {
    let server = server.normalized();
    let path = normalize_remote_path(path.into());
    let (mut session, sftp) = connect_sftp(&server).await?;

    if is_dir {
        sftp.remove_dir(&path)
            .await
            .with_context(|| format!("删除远端目录失败：{path}"))?;
    } else {
        sftp.remove_file(&path)
            .await
            .with_context(|| format!("删除远端文件失败：{path}"))?;
    }

    shutdown_sftp(&mut session, &sftp).await;
    Ok(path)
}

pub fn join_remote_path(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        name.to_string()
    } else if dir == "/" {
        format!("/{name}")
    } else {
        format!("{}/{}", dir.trim_end_matches('/'), name)
    }
}

pub fn local_file_name(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
        .ok_or_else(|| anyhow!("无法从本地路径中识别文件名：{}", path.display()))
}

fn normalize_remote_path(path: String) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        trimmed.replace('\\', "/")
    }
}

async fn connect_sftp(server: &Server) -> Result<(client::Handle<SSHClient>, SftpSession)> {
    let policy = server.connection_policy.normalized();
    let connect_timeout = Duration::from_secs(policy.connect_timeout_secs);
    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(policy.connect_timeout_secs * 3)),
        keepalive_interval: Some(Duration::from_secs(policy.keepalive_interval_secs)),
        keepalive_max: policy.keepalive_max_misses,
        ..Config::default()
    });

    // 复用终端连接里的主机指纹校验逻辑，保证 SFTP 和终端遵循同一套信任策略。
    let (event_tx, _event_rx) = unbounded_channel();
    let handler = SSHClient::new(server.clone(), event_tx);

    let mut session = timeout(
        connect_timeout,
        client::connect(config, (server.host.as_str(), server.port), handler),
    )
    .await
    .with_context(|| format!("连接远端 SFTP 在 {} 秒后超时", policy.connect_timeout_secs))?
    .with_context(|| format!("无法连接到 {}:{}", server.host, server.port))?;

    timeout(connect_timeout, authenticate_server(server, &mut session))
        .await
        .with_context(|| format!("SFTP 认证在 {} 秒后超时", policy.connect_timeout_secs))??;

    let channel = timeout(connect_timeout, session.channel_open_session())
        .await
        .with_context(|| format!("打开 SFTP 通道在 {} 秒后超时", policy.connect_timeout_secs))?
        .context("打开 SFTP 会话通道失败")?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("启动远端 SFTP 子系统失败")?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("初始化 SFTP 会话失败")?;

    Ok((session, sftp))
}

async fn authenticate_server(
    server: &Server,
    session: &mut client::Handle<SSHClient>,
) -> Result<()> {
    match server.auth_method {
        AuthMethod::Password => {
            let password = match server
                .password
                .as_deref()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
            {
                Some(password) => password,
                None => load_server_password(server)?
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("密码认证需要先配置密码"))?,
            };

            let auth_result = session
                .authenticate_password(server.user.clone(), password)
                .await
                .context("发起 SFTP 密码认证请求失败")?;

            if !auth_result {
                bail!("用户 {} 的 SFTP 密码认证失败", server.user);
            }
        }
        AuthMethod::PrivateKey => {
            let private_key_path = server
                .private_key_path
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("私钥认证需要填写密钥路径"))?;

            let private_key = load_secret_key(private_key_path, None)
                .with_context(|| format!("加载私钥失败：{private_key_path}"))?;

            let auth_result = session
                .authenticate_publickey(server.user.clone(), Arc::new(private_key))
                .await
                .context("发起 SFTP 私钥认证请求失败")?;

            if !auth_result {
                bail!("用户 {} 的 SFTP 私钥认证失败", server.user);
            }
        }
    }

    Ok(())
}

async fn shutdown_sftp(session: &mut client::Handle<SSHClient>, sftp: &SftpSession) {
    let _ = sftp.close().await;
    let _ = session
        .disconnect(Disconnect::ByApplication, "SFTP 操作完成", "zh-CN")
        .await;
}
