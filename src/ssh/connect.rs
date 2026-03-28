use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use russh::client::{self, Config};
use russh::{ChannelMsg, Disconnect};
use russh_keys::load_secret_key;
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::time::{sleep, timeout};

use crate::audit::log::append_server_event;
use crate::config::server::{AuthMethod, ConnectionPolicy, Server};
use crate::security::secrets::load_server_password;
use crate::ssh::client::SSHClient;

#[derive(Debug)]
pub enum SessionCommand {
    Send(Vec<u8>),
    Resize {
        cols: u32,
        rows: u32,
        width_px: u32,
        height_px: u32,
    },
    Interrupt,
    ReconnectNow,
    Disconnect,
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    Status(String),
    Connected {
        message: String,
        attempt: u32,
    },
    Retrying {
        message: String,
        attempt: u32,
        delay_secs: u64,
    },
    Output(String),
    Error(String),
    Disconnected(String),
}

#[derive(Clone)]
pub struct SessionHandle {
    command_tx: UnboundedSender<SessionCommand>,
}

impl SessionHandle {
    pub fn send_input(&self, data: impl Into<Vec<u8>>) -> Result<()> {
        self.command_tx
            .send(SessionCommand::Send(data.into()))
            .map_err(|_| anyhow!("SSH 会话已不可用"))
    }

    pub fn resize(&self, cols: u32, rows: u32, width_px: u32, height_px: u32) -> Result<()> {
        self.command_tx
            .send(SessionCommand::Resize {
                cols,
                rows,
                width_px,
                height_px,
            })
            .map_err(|_| anyhow!("SSH 会话已不可用"))
    }

    pub fn interrupt(&self) -> Result<()> {
        self.command_tx
            .send(SessionCommand::Interrupt)
            .map_err(|_| anyhow!("SSH 会话已不可用"))
    }

    pub fn reconnect_now(&self) -> Result<()> {
        self.command_tx
            .send(SessionCommand::ReconnectNow)
            .map_err(|_| anyhow!("SSH 会话已不可用"))
    }

    pub fn disconnect(&self) -> Result<()> {
        self.command_tx
            .send(SessionCommand::Disconnect)
            .map_err(|_| anyhow!("SSH 会话已不可用"))
    }
}

pub struct ManagedSession {
    pub handle: SessionHandle,
    pub events: UnboundedReceiver<SessionEvent>,
}

#[derive(Debug, Clone, Copy)]
struct TerminalSize {
    cols: u32,
    rows: u32,
    width_px: u32,
    height_px: u32,
}

impl Default for TerminalSize {
    fn default() -> Self {
        Self {
            cols: 140,
            rows: 40,
            width_px: 1280,
            height_px: 720,
        }
    }
}

impl TerminalSize {
    fn new(cols: u32, rows: u32, width_px: u32, height_px: u32) -> Self {
        Self {
            cols: cols.max(20),
            rows: rows.max(5),
            width_px,
            height_px,
        }
    }
}

enum SessionOutcome {
    UserDisconnected(String),
    UiDetached(String),
    ReconnectNow(String),
    RecoverableFailure(String),
}

enum RetryGateOutcome {
    ContinueAfterDelay,
    ContinueImmediately,
    UserDisconnected(String),
    UiDetached(String),
}

pub fn connect_ssh(runtime: Arc<Runtime>, server: Server) -> ManagedSession {
    let (command_tx, command_rx) = unbounded_channel();
    let (event_tx, event_rx) = unbounded_channel();

    runtime.spawn(run_session(server.normalized(), command_rx, event_tx));

    ManagedSession {
        handle: SessionHandle { command_tx },
        events: event_rx,
    }
}

async fn run_session(
    server: Server,
    mut command_rx: UnboundedReceiver<SessionCommand>,
    event_tx: UnboundedSender<SessionEvent>,
) {
    let policy = server.connection_policy.normalized();
    let mut terminal_size = TerminalSize::default();
    let mut attempt = 1_u32;

    loop {
        let outcome = match run_connection_attempt(
            &server,
            &policy,
            attempt,
            &mut terminal_size,
            &mut command_rx,
            &event_tx,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                let reason = format!("{error:#}");
                append_server_event(&server, "连接错误", &reason);
                send_event(&event_tx, SessionEvent::Error(reason.clone()));
                SessionOutcome::RecoverableFailure(reason)
            }
        };

        match outcome {
            SessionOutcome::UserDisconnected(message) | SessionOutcome::UiDetached(message) => {
                append_server_event(&server, "连接关闭", &message);
                send_event(&event_tx, SessionEvent::Disconnected(message));
                break;
            }
            SessionOutcome::ReconnectNow(reason) => {
                attempt += 1;
                append_server_event(&server, "请求重连", &reason);
                send_event(
                    &event_tx,
                    SessionEvent::Retrying {
                        message: format!("{reason} 即将立即重连。"),
                        attempt,
                        delay_secs: 0,
                    },
                );
            }
            SessionOutcome::RecoverableFailure(reason) => {
                if !should_retry(&policy, attempt) {
                    let final_message = if policy.auto_reconnect {
                        format!(
                            "{reason} 自动恢复在重试 {} 次后停止。",
                            policy.max_reconnect_attempts
                        )
                    } else {
                        reason
                    };
                    append_server_event(&server, "连接关闭", &final_message);
                    send_event(&event_tx, SessionEvent::Disconnected(final_message));
                    break;
                }

                let next_attempt = attempt + 1;
                let delay_secs = policy.reconnect_backoff_secs;
                append_server_event(
                    &server,
                    "计划重试",
                    &format!("{reason} attempt={next_attempt} delay_secs={delay_secs}"),
                );
                send_event(
                    &event_tx,
                    SessionEvent::Retrying {
                        message: format!(
                            "{reason} 将在 {delay_secs} 秒后重试（第 {next_attempt}/{} 次）...",
                            total_attempts(&policy)
                        ),
                        attempt: next_attempt,
                        delay_secs,
                    },
                );

                match wait_for_retry_window(
                    delay_secs,
                    &mut terminal_size,
                    &mut command_rx,
                    &event_tx,
                )
                .await
                {
                    RetryGateOutcome::ContinueAfterDelay
                    | RetryGateOutcome::ContinueImmediately => {
                        attempt = next_attempt;
                    }
                    RetryGateOutcome::UserDisconnected(message)
                    | RetryGateOutcome::UiDetached(message) => {
                        send_event(&event_tx, SessionEvent::Disconnected(message));
                        break;
                    }
                }
            }
        }
    }
}

async fn run_connection_attempt(
    server: &Server,
    policy: &ConnectionPolicy,
    attempt: u32,
    terminal_size: &mut TerminalSize,
    command_rx: &mut UnboundedReceiver<SessionCommand>,
    event_tx: &UnboundedSender<SessionEvent>,
) -> Result<SessionOutcome> {
    let connect_timeout = Duration::from_secs(policy.connect_timeout_secs);

    send_event(
        event_tx,
        SessionEvent::Status(format!(
            "正在连接 {}（第 {attempt}/{} 次）...",
            server.endpoint(),
            total_attempts(policy)
        )),
    );
    append_server_event(
        server,
        "连接尝试",
        &format!(
            "attempt={attempt} total_attempts={}",
            total_attempts(policy)
        ),
    );

    let config = Arc::new(Config {
        inactivity_timeout: Some(Duration::from_secs(policy.connect_timeout_secs * 3)),
        keepalive_interval: Some(Duration::from_secs(policy.keepalive_interval_secs)),
        keepalive_max: policy.keepalive_max_misses,
        ..Config::default()
    });

    let handler = SSHClient::new(server.clone(), event_tx.clone());
    let mut session = timeout(
        connect_timeout,
        client::connect(config, (server.host.as_str(), server.port), handler),
    )
    .await
    .with_context(|| format!("连接在 {} 秒后超时", policy.connect_timeout_secs))?
    .with_context(|| format!("无法连接到 {}:{}", server.host, server.port))?;

    timeout(
        connect_timeout,
        authenticate_server(server, &mut session, event_tx),
    )
    .await
    .with_context(|| format!("认证在 {} 秒后超时", policy.connect_timeout_secs))??;

    let mut channel = timeout(connect_timeout, session.channel_open_session())
        .await
        .with_context(|| format!("打开 SSH 会话在 {} 秒后超时", policy.connect_timeout_secs))?
        .context("打开 SSH 会话通道失败")?;

    let size = *terminal_size;
    timeout(
        connect_timeout,
        channel.request_pty(
            true,
            "xterm-256color",
            size.cols,
            size.rows,
            size.width_px,
            size.height_px,
            &[],
        ),
    )
    .await
    .with_context(|| format!("PTY 协商在 {} 秒后超时", policy.connect_timeout_secs))?
    .context("申请远端 PTY 失败")?;

    timeout(connect_timeout, channel.request_shell(true))
        .await
        .with_context(|| format!("启动远端 Shell 在 {} 秒后超时", policy.connect_timeout_secs))?
        .context("启动远端 Shell 失败")?;

    send_event(
        event_tx,
        SessionEvent::Connected {
            message: format!("已连接到 {}。", server.endpoint()),
            attempt,
        },
    );
    append_server_event(server, "连接成功", &format!("attempt={attempt}"));

    loop {
        tokio::select! {
            maybe_command = command_rx.recv() => {
                match maybe_command {
                    Some(SessionCommand::Send(data)) => {
                        if !data.is_empty() {
                            channel
                                .data(&data[..])
                                .await
                                .context("发送输入到远端 Shell 失败")?;
                        }
                    }
                    Some(SessionCommand::Resize { cols, rows, width_px, height_px }) => {
                        *terminal_size = TerminalSize::new(cols, rows, width_px, height_px);
                        channel
                            .window_change(
                                terminal_size.cols,
                                terminal_size.rows,
                                terminal_size.width_px,
                                terminal_size.height_px,
                            )
                            .await
                            .context("调整远端 PTY 大小失败")?;
                    }
                    Some(SessionCommand::Interrupt) => {
                        channel
                            .data(&[3_u8][..])
                            .await
                            .context("向远端 Shell 发送 Ctrl+C 失败")?;
                    }
                    Some(SessionCommand::ReconnectNow) => {
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        let _ = session
                            .disconnect(Disconnect::ByApplication, "用户请求立即重连", "zh-CN")
                            .await;
                        return Ok(SessionOutcome::ReconnectNow("已请求立即重连。".to_string()));
                    }
                    Some(SessionCommand::Disconnect) => {
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        let _ = session
                            .disconnect(Disconnect::ByApplication, "用户请求断开连接", "zh-CN")
                            .await;
                        return Ok(SessionOutcome::UserDisconnected("已按用户请求断开连接。".to_string()));
                    }
                    None => {
                        let _ = session
                            .disconnect(Disconnect::ByApplication, "界面通道已关闭", "zh-CN")
                            .await;
                        return Ok(SessionOutcome::UiDetached("终端界面已断开。".to_string()));
                    }
                }
            }
            maybe_message = channel.wait() => {
                match maybe_message {
                    Some(ChannelMsg::Data { data }) => {
                        let output = sanitize_terminal_text(data.as_ref());
                        if !output.is_empty() {
                            send_event(event_tx, SessionEvent::Output(output));
                        }
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let output = sanitize_terminal_text(data.as_ref());
                        if !output.is_empty() {
                            send_event(event_tx, SessionEvent::Output(output));
                        }
                    }
                    Some(ChannelMsg::Success) => {}
                    Some(ChannelMsg::Failure) => {
                        send_event(
                            event_tx,
                            SessionEvent::Status("服务器拒绝了最近一次通道请求。".to_string()),
                        );
                    }
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        let message = format!("远端 Shell 已退出，状态码为 {exit_status}。");
                        let _ = session
                            .disconnect(Disconnect::ByApplication, &message, "zh-CN")
                            .await;
                        return Ok(SessionOutcome::RecoverableFailure(message));
                    }
                    Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                        let message = format!("远端 Shell 因信号 {signal_name:?} 退出。");
                        let _ = session
                            .disconnect(Disconnect::ByApplication, &message, "zh-CN")
                            .await;
                        return Ok(SessionOutcome::RecoverableFailure(message));
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                        return Ok(SessionOutcome::RecoverableFailure("远端会话已关闭。".to_string()));
                    }
                    Some(ChannelMsg::WindowAdjusted { .. }) | Some(ChannelMsg::XonXoff { .. }) => {}
                    Some(_) => {}
                }
            }
        }
    }
}

async fn wait_for_retry_window(
    delay_secs: u64,
    terminal_size: &mut TerminalSize,
    command_rx: &mut UnboundedReceiver<SessionCommand>,
    event_tx: &UnboundedSender<SessionEvent>,
) -> RetryGateOutcome {
    if delay_secs == 0 {
        return RetryGateOutcome::ContinueImmediately;
    }

    let mut input_notice_sent = false;
    let timer = sleep(Duration::from_secs(delay_secs));
    tokio::pin!(timer);

    loop {
        tokio::select! {
            _ = &mut timer => return RetryGateOutcome::ContinueAfterDelay,
            maybe_command = command_rx.recv() => {
                match maybe_command {
                    Some(SessionCommand::Resize { cols, rows, width_px, height_px }) => {
                        *terminal_size = TerminalSize::new(cols, rows, width_px, height_px);
                    }
                    Some(SessionCommand::ReconnectNow) => {
                        return RetryGateOutcome::ContinueImmediately;
                    }
                    Some(SessionCommand::Disconnect) => {
                        return RetryGateOutcome::UserDisconnected("已按用户请求断开连接。".to_string());
                    }
                    Some(SessionCommand::Send(_)) | Some(SessionCommand::Interrupt) => {
                        if !input_notice_sent {
                            send_event(
                                event_tx,
                                SessionEvent::Status("会话正在重连，输入会在下次连接成功后恢复发送。".to_string()),
                            );
                            input_notice_sent = true;
                        }
                    }
                    None => {
                        return RetryGateOutcome::UiDetached("终端界面已断开。".to_string());
                    }
                }
            }
        }
    }
}

async fn authenticate_server(
    server: &Server,
    session: &mut client::Handle<SSHClient>,
    event_tx: &UnboundedSender<SessionEvent>,
) -> Result<()> {
    send_event(
        event_tx,
        SessionEvent::Status(format!(
            "正在以 {} 身份使用{}认证...",
            server.user,
            server.auth_method.label()
        )),
    );

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
                .context("发起密码认证请求失败")?;

            if !auth_result {
                bail!("用户 {} 的密码认证失败", server.user);
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
                .context("发起私钥认证请求失败")?;

            if !auth_result {
                bail!("用户 {} 的私钥认证失败", server.user);
            }
        }
    }

    send_event(event_tx, SessionEvent::Status("认证成功。".to_string()));
    append_server_event(server, "认证成功", "SSH 认证成功。");

    Ok(())
}

fn should_retry(policy: &ConnectionPolicy, attempt: u32) -> bool {
    policy.auto_reconnect && attempt.saturating_sub(1) < policy.max_reconnect_attempts
}

fn total_attempts(policy: &ConnectionPolicy) -> u32 {
    1 + if policy.auto_reconnect {
        policy.max_reconnect_attempts
    } else {
        0
    }
}

fn send_event(event_tx: &UnboundedSender<SessionEvent>, event: SessionEvent) {
    let _ = event_tx.send(event);
}

fn sanitize_terminal_text(input: &[u8]) -> String {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        match input[index] {
            0x1b => {
                index += 1;
                if index >= input.len() {
                    break;
                }

                match input[index] {
                    b'[' => {
                        index += 1;
                        while index < input.len() {
                            let byte = input[index];
                            index += 1;
                            if (0x40..=0x7e).contains(&byte) {
                                break;
                            }
                        }
                    }
                    b']' => {
                        index += 1;
                        while index < input.len() {
                            match input[index] {
                                0x07 => {
                                    index += 1;
                                    break;
                                }
                                0x1b if index + 1 < input.len() && input[index + 1] == b'\\' => {
                                    index += 2;
                                    break;
                                }
                                _ => index += 1,
                            }
                        }
                    }
                    _ => {
                        while index < input.len() {
                            let byte = input[index];
                            index += 1;
                            if (0x40..=0x7e).contains(&byte) {
                                break;
                            }
                        }
                    }
                }
            }
            b'\r' => {
                if input.get(index + 1) == Some(&b'\n') {
                    output.push(b'\n');
                    index += 2;
                } else {
                    output.push(b'\n');
                    index += 1;
                }
            }
            0x08 => {
                let _ = output.pop();
                index += 1;
            }
            0 => {
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&output).to_string()
}
