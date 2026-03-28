use anyhow::{Context, Result};
use russh::client::{DisconnectReason, Handler};
use russh_keys::{Error as RusshKeyError, check_known_hosts, key::PublicKey, learn_known_hosts};
use tokio::sync::mpsc::UnboundedSender;

use crate::config::server::Server;
use crate::ssh::connect::SessionEvent;

pub struct SSHClient {
    server: Server,
    event_tx: UnboundedSender<SessionEvent>,
}

impl SSHClient {
    pub fn new(server: Server, event_tx: UnboundedSender<SessionEvent>) -> Self {
        Self { server, event_tx }
    }

    fn emit(&self, event: SessionEvent) {
        let _ = self.event_tx.send(event);
    }
}

#[async_trait::async_trait]
impl Handler for SSHClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        match check_known_hosts(&self.server.host, self.server.port, server_public_key) {
            Ok(true) => {
                self.emit(SessionEvent::Status(
                    "主机指纹已通过 known_hosts 校验。".to_string(),
                ));
                Ok(true)
            }
            Ok(false) => {
                learn_known_hosts(&self.server.host, self.server.port, server_public_key)
                    .context("写入 known_hosts 主机指纹失败")?;
                self.emit(SessionEvent::Status(
                    "首次连接已信任，并写入 known_hosts。".to_string(),
                ));
                Ok(true)
            }
            Err(RusshKeyError::KeyChanged { line }) => {
                self.emit(SessionEvent::Error(format!(
                    "检测到主机指纹不匹配，known_hosts 第 {line} 行与当前服务器指纹不一致。"
                )));
                Ok(false)
            }
            Err(error) => Err(anyhow::Error::new(error)).context("主机指纹校验失败"),
        }
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let banner = banner.trim();
        if !banner.is_empty() {
            self.emit(SessionEvent::Status(format!("服务器横幅：{banner}")));
        }
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                let message = if info.message.trim().is_empty() {
                    format!("服务器已断开连接，原因码：{:?}。", info.reason_code)
                } else {
                    format!("服务器已断开连接：{}", info.message.trim())
                };
                self.emit(SessionEvent::Status(message));
                Ok(())
            }
            DisconnectReason::Error(error) => {
                self.emit(SessionEvent::Error(format!("传输层错误：{error:#}")));
                Err(error)
            }
        }
    }
}
