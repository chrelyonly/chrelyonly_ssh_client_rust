use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use chrono::{Local, TimeZone};
use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Mesh,
    RichText, Shadow, Stroke, TextEdit, TextStyle, pos2, text::{LayoutJob, TextFormat}, vec2,
};
use egui_extras::{Size, StripBuilder};
use egui_notify::{Anchor as ToastAnchor, Toasts};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::audit::log::{
    append_command_event, append_server_event, audit_log_path, legacy_audit_log_path,
};
use crate::config::paths::{data_dir, temp_dir};
use crate::config::preferences::{AppSettings, ThemePreset, load_settings, save_settings};
use crate::config::server::{AuthMethod, ConnectionPolicy, DEFAULT_GROUP_NAME, Server};
use crate::config::storage::save_servers;
use crate::config::sync::{
    LoginOutcome, SyncSnapshot, authenticate_or_create_account, pull_snapshot, push_snapshot,
};
use crate::history::history::{
    CommandHistory, ConnectionHistory, Script, ShortcutCommand, load_command_history,
    load_connection_history, load_scripts, load_shortcuts, save_command_history,
    save_connection_history, save_scripts, save_shortcuts,
};
use crate::security::secrets::store_server_password;
use crate::ssh::connect::{AuthPromptSpec, ManagedSession, SessionEvent, SessionHandle, connect_ssh};
use crate::ssh::sftp::{
    RemoteFileEntry, create_dir as sftp_create_dir, download_file as sftp_download_file,
    join_remote_path as join_sftp_path, list_dir as sftp_list_dir,
    local_file_name as sftp_local_file_name, remove_path as sftp_remove_path,
    upload_file as sftp_upload_file,
};

const MAX_TERMINAL_CHARS: usize = 250_000;
const DEFAULT_TERMINAL_COLS: u32 = 140;
const DEFAULT_TERMINAL_ROWS: u32 = 40;
const HISTORY_LIMIT: usize = 20;
const HISTORY_GROUP_LIMIT: usize = 8;

const BODY_FONT_NAME: &str = "ui_body";
const DISPLAY_FONT_NAME: &str = "display";
const TERMINAL_FONT_NAME: &str = "terminal_ui";
const BACKGROUND_IMAGE_BYTES: &[u8] = include_bytes!("../resource/image/bg.jpg");

const BUILTIN_SHORTCUTS: [(&str, &str, &str); 5] = [
    (
        "系统概览",
        "uname -a && uptime && whoami",
        "快速查看主机身份、运行时长和系统指纹。",
    ),
    ("磁盘使用", "df -h", "检查磁盘挂载情况与剩余空间。"),
    (
        "内存压力",
        "free -m && top -bn1 | head -n 5",
        "查看内存占用和当前最繁忙的进程。",
    ),
    (
        "故障服务",
        "systemctl --failed",
        "列出 Linux 主机中失败的 systemd 服务。",
    ),
    (
        "监听端口",
        "ss -tulpn | head -n 30",
        "检查当前监听中的网络端口。",
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TabState {
    Connecting,
    Reconnecting,
    Connected,
    Disconnected,
    Failed,
}

struct Tab {
    id: usize,
    title: String,
    server: Server,
    terminal_content: String,
    input_buffer: String,
    status_text: String,
    state: TabState,
    auto_scroll: bool,
    unseen_output: bool,
    history_cursor: Option<usize>,
    last_terminal_size: Option<(u32, u32)>,
    connection_attempt: u32,
    reconnect_count: u32,
    connected_at: Option<Instant>,
    retry_delay_secs: Option<u64>,
    session: SessionHandle,
    events: UnboundedReceiver<SessionEvent>,
}

impl Tab {
    fn new(
        id: usize,
        server: Server,
        session: SessionHandle,
        events: UnboundedReceiver<SessionEvent>,
    ) -> Self {
        let terminal_content = format!(
            "# 正在打开安全终端会话...\n# 目标: {}\n\n",
            server.endpoint()
        );

        Self {
            id,
            title: server.name.clone(),
            server,
            terminal_content,
            input_buffer: String::new(),
            status_text: "连接中...".to_string(),
            state: TabState::Connecting,
            auto_scroll: true,
            unseen_output: false,
            history_cursor: None,
            last_terminal_size: None,
            connection_attempt: 1,
            reconnect_count: 0,
            connected_at: None,
            retry_delay_secs: None,
            session,
            events,
        }
    }

    fn title_for_tab(&self) -> String {
        let unread = if self.unseen_output { "* " } else { "" };
        let suffix = match self.state {
            TabState::Connecting => " ...",
            TabState::Reconnecting => " (恢复中)",
            TabState::Connected => "",
            TabState::Disconnected => " (已关闭)",
            TabState::Failed => " (失败)",
        };
        format!("{unread}{} · #{}{}", self.title, self.id, suffix)
    }

    fn push_output(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }

        self.terminal_content.push_str(text);
        if self.terminal_content.len() <= MAX_TERMINAL_CHARS {
            return;
        }

        let overflow = self.terminal_content.len() - MAX_TERMINAL_CHARS;
        let mut boundary = overflow;
        while boundary < self.terminal_content.len()
            && !self.terminal_content.is_char_boundary(boundary)
        {
            boundary += 1;
        }
        if let Some(newline_offset) = self.terminal_content[boundary..].find('\n') {
            boundary += newline_offset + 1;
        }
        self.terminal_content.drain(..boundary);
    }

    fn push_system_message(&mut self, message: &str) {
        self.push_output(&format!("\n# {message}\n"));
    }

    fn terminal_identity(&self) -> String {
        format!("{}@{}", self.server.user, self.server.host)
    }

    fn status_color(&self, palette: &ThemePalette) -> Color32 {
        match self.state {
            TabState::Connecting => palette.warning,
            TabState::Reconnecting => palette.accent,
            TabState::Connected => palette.success,
            TabState::Disconnected => palette.text_muted,
            TabState::Failed => palette.danger,
        }
    }

    fn navigate_history(&mut self, commands: &[String], older: bool) {
        if commands.is_empty() {
            return;
        }

        let next = if older {
            match self.history_cursor {
                Some(cursor) => (cursor + 1).min(commands.len() - 1),
                None => 0,
            }
        } else {
            match self.history_cursor {
                Some(0) => {
                    self.history_cursor = None;
                    self.input_buffer.clear();
                    return;
                }
                Some(cursor) => cursor - 1,
                None => return,
            }
        };

        self.history_cursor = Some(next);
        self.input_buffer = commands[next].clone();
    }

    fn prepare_for_new_session(
        &mut self,
        session: SessionHandle,
        events: UnboundedReceiver<SessionEvent>,
    ) {
        self.session = session;
        self.events = events;
        self.state = TabState::Connecting;
        self.status_text = "连接中...".to_string();
        self.unseen_output = false;
        self.history_cursor = None;
        self.connection_attempt = 1;
        self.reconnect_count = 0;
        self.connected_at = None;
        self.retry_delay_secs = None;
        self.push_system_message("正在启动新的会话生命周期。");
    }

    fn uptime_text(&self) -> String {
        match self.connected_at {
            Some(connected_at) => format_duration(connected_at.elapsed()),
            None => "--".to_string(),
        }
    }
}

struct FlashMessage {
    text: String,
    is_error: bool,
    created_at: Instant,
}

struct AuthPromptDialog {
    tab_id: usize,
    title: String,
    instructions: String,
    prompts: Vec<AuthPromptSpec>,
    responses: Vec<String>,
}

impl Default for FlashMessage {
    fn default() -> Self {
        Self {
            text: String::new(),
            is_error: false,
            created_at: Instant::now(),
        }
    }
}

#[derive(Debug)]
struct ServerForm {
    name: String,
    host: String,
    port: String,
    user: String,
    password: String,
    group: String,
    auth_method: AuthMethod,
    private_key_path: String,
    connect_timeout_secs: String,
    keepalive_interval_secs: String,
    keepalive_max_misses: String,
    auto_reconnect: bool,
    max_reconnect_attempts: String,
    reconnect_backoff_secs: String,
}

impl Default for ServerForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            host: String::new(),
            port: "22".to_string(),
            user: String::new(),
            password: String::new(),
            group: DEFAULT_GROUP_NAME.to_string(),
            auth_method: AuthMethod::Password,
            private_key_path: String::new(),
            connect_timeout_secs: "10".to_string(),
            keepalive_interval_secs: "15".to_string(),
            keepalive_max_misses: "4".to_string(),
            auto_reconnect: true,
            max_reconnect_attempts: "3".to_string(),
            reconnect_backoff_secs: "5".to_string(),
        }
    }
}

impl ServerForm {
    fn build_server(&self) -> Result<Server> {
        let parsed_target = parse_ssh_target(self.host.trim());
        let host = parsed_target.host.as_str();
        let user = if self.user.trim().is_empty() {
            parsed_target.user.as_deref().unwrap_or("")
        } else {
            self.user.trim()
        };
        if host.is_empty() {
            bail!("请输入主机地址。");
        }
        if user.is_empty() {
            bail!("请输入用户名。");
        }

        let port: u16 = self
            .port
            .trim()
            .parse()
            .map_err(|_| anyhow!("端口必须是有效数字。"))?;
        let port = parsed_target.port.unwrap_or(port);
        let connect_timeout_secs: u64 = self
            .connect_timeout_secs
            .trim()
            .parse()
            .map_err(|_| anyhow!("连接超时必须是有效数字。"))?;
        let keepalive_interval_secs: u64 = self
            .keepalive_interval_secs
            .trim()
            .parse()
            .map_err(|_| anyhow!("保活间隔必须是有效数字。"))?;
        let keepalive_max_misses: usize = self
            .keepalive_max_misses
            .trim()
            .parse()
            .map_err(|_| anyhow!("保活丢失上限必须是有效数字。"))?;
        let max_reconnect_attempts: u32 = self
            .max_reconnect_attempts
            .trim()
            .parse()
            .map_err(|_| anyhow!("重连次数必须是有效数字。"))?;
        let reconnect_backoff_secs: u64 = self
            .reconnect_backoff_secs
            .trim()
            .parse()
            .map_err(|_| anyhow!("重连退避必须是有效数字。"))?;
        let name = if self.name.trim().is_empty() {
            format!("{user}@{host}")
        } else {
            self.name.trim().to_string()
        };

        Ok(Server {
            name,
            host: host.to_string(),
            port,
            user: user.to_string(),
            password: option_from_text(&self.password),
            group: if self.group.trim().is_empty() {
                DEFAULT_GROUP_NAME.to_string()
            } else {
                self.group.trim().to_string()
            },
            auth_method: self.auth_method,
            private_key_path: option_from_text(&self.private_key_path),
            password_in_keyring: false,
            connection_policy: ConnectionPolicy {
                connect_timeout_secs,
                keepalive_interval_secs,
                keepalive_max_misses,
                auto_reconnect: self.auto_reconnect,
                max_reconnect_attempts,
                reconnect_backoff_secs,
            },
        }
        .normalized())
    }

    fn fill_from_server(&mut self, server: &Server) {
        self.name = server.name.clone();
        self.host = server.host.clone();
        self.port = server.port.to_string();
        self.user = server.user.clone();
        self.password.clear();
        self.group = server.group_name().to_string();
        self.auth_method = server.auth_method;
        self.private_key_path = server.private_key_path.clone().unwrap_or_default();
        self.connect_timeout_secs = server.connection_policy.connect_timeout_secs.to_string();
        self.keepalive_interval_secs = server.connection_policy.keepalive_interval_secs.to_string();
        self.keepalive_max_misses = server.connection_policy.keepalive_max_misses.to_string();
        self.auto_reconnect = server.connection_policy.auto_reconnect;
        self.max_reconnect_attempts = server.connection_policy.max_reconnect_attempts.to_string();
        self.reconnect_backoff_secs = server.connection_policy.reconnect_backoff_secs.to_string();
    }

    fn fill_from_history(&mut self, entry: &ConnectionHistory) {
        self.name = entry.server_name.clone();
        self.host = entry.host.clone();
        self.port = entry.port.to_string();
        self.user = entry.user.clone();
        self.password.clear();
        self.group = if entry.server_group.trim().is_empty() {
            DEFAULT_GROUP_NAME.to_string()
        } else {
            entry.server_group.clone()
        };
        self.auth_method = AuthMethod::Password;
        self.private_key_path.clear();
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Default)]
struct SyncForm {
    username: String,
    password: String,
}

#[derive(Default)]
struct ScriptForm {
    name: String,
    description: String,
    content: String,
}

impl ScriptForm {
    fn fill_from_script(&mut self, script: &Script) {
        self.name = script.name.clone();
        self.description = script.description.clone();
        self.content = script.content.clone();
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Default)]
struct FileTransferPanel {
    server_key: Option<String>,
    remote_path: String,
    local_path: String,
    new_directory_name: String,
    selected_remote_path: Option<String>,
    entries: Vec<RemoteFileEntry>,
    busy_label: Option<String>,
    status_text: String,
}

impl FileTransferPanel {
    fn new() -> Self {
        Self {
            server_key: None,
            remote_path: ".".to_string(),
            local_path: default_transfer_path().display().to_string(),
            new_directory_name: String::new(),
            selected_remote_path: None,
            entries: Vec::new(),
            busy_label: None,
            status_text: "打开标签页后即可浏览远端文件与传输内容。".to_string(),
        }
    }

    fn is_busy(&self) -> bool {
        self.busy_label.is_some()
    }

    fn reset_for_server(&mut self, server: &Server) -> bool {
        let server_key = server.server_key();
        if self.server_key.as_deref() == Some(server_key.as_str()) {
            return false;
        }

        self.server_key = Some(server_key);
        self.remote_path = ".".to_string();
        self.new_directory_name.clear();
        self.selected_remote_path = None;
        self.entries.clear();
        self.busy_label = None;
        self.status_text = format!("已切换到 {}，可以刷新远端目录。", server.endpoint());
        true
    }

    fn selected_entry(&self) -> Option<&RemoteFileEntry> {
        self.selected_remote_path
            .as_ref()
            .and_then(|path| self.entries.iter().find(|entry| &entry.full_path == path))
    }
}

enum FileTransferEvent {
    DirectoryLoaded {
        server: Server,
        path: String,
        entries: Vec<RemoteFileEntry>,
    },
    Downloaded {
        server: Server,
        remote_path: String,
        local_path: PathBuf,
    },
    Uploaded {
        server: Server,
        remote_path: String,
        local_path: PathBuf,
    },
    DirectoryCreated {
        server: Server,
        path: String,
    },
    Removed {
        server: Server,
        path: String,
        is_dir: bool,
    },
    Error {
        server: Option<Server>,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceTab {
    Overview,
    Files,
    Commands,
    History,
    Scripts,
    Audit,
    Workspace,
}

impl ResourceTab {
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "概览",
            Self::Files => "文件",
            Self::Commands => "命令",
            Self::History => "历史",
            Self::Scripts => "脚本",
            Self::Audit => "审计",
            Self::Workspace => "工作台",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HomePage {
    Hosts,
    Sync,
    Scripts,
    History,
    Audit,
}

impl HomePage {
    fn label(self) -> &'static str {
        match self {
            Self::Hosts => "主机",
            Self::Sync => "同步",
            Self::Scripts => "脚本",
            Self::History => "历史",
            Self::Audit => "日志",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppPage {
    Terminal,
    Connections,
    Settings,
    Config,
}

impl AppPage {
    fn label(self) -> &'static str {
        match self {
            Self::Terminal => "终端",
            Self::Connections => "连接",
            Self::Settings => "设置",
            Self::Config => "配置",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalWorkbenchTab {
    SplitTerminal,
    Vault,
    Sftp,
    Theme,
}

impl TerminalWorkbenchTab {
    fn label(self) -> &'static str {
        match self {
            Self::SplitTerminal => "终端会话",
            Self::Vault => "连接资料",
            Self::Sftp => "SFTP",
            Self::Theme => "自定义主题",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::SplitTerminal => "SSH 会话、标签切换与终端操作",
            Self::Vault => "连接信息、命令记录与审计资料",
            Self::Sftp => "远程文件浏览、上传下载与整理",
            Self::Theme => "统一控制 SSH 客户端的视觉风格",
        }
    }
}

#[derive(Clone, Copy)]
struct ThemePalette {
    background_top: Color32,
    background_bottom: Color32,
    mist: Color32,
    blossom: Color32,
    panel: Color32,
    panel_soft: Color32,
    panel_alt: Color32,
    stroke: Color32,
    accent: Color32,
    accent_soft: Color32,
    text_primary: Color32,
    text_secondary: Color32,
    text_muted: Color32,
    success: Color32,
    warning: Color32,
    danger: Color32,
    shadow: Color32,
    terminal_bg: Color32,
    terminal_border: Color32,
    terminal_text: Color32,
}

impl ThemePalette {
    fn from_preset(preset: ThemePreset) -> Self {
        match preset {
            ThemePreset::PeachBlossom => Self {
                background_top: Color32::from_rgb(24, 36, 58),
                background_bottom: Color32::from_rgb(8, 14, 28),
                mist: Color32::from_rgba_premultiplied(255, 255, 255, 28),
                blossom: Color32::from_rgba_premultiplied(146, 193, 255, 44),
                panel: Color32::from_rgba_premultiplied(17, 28, 46, 124),
                panel_soft: Color32::from_rgba_premultiplied(24, 37, 60, 108),
                panel_alt: Color32::from_rgba_premultiplied(34, 50, 77, 144),
                stroke: Color32::from_rgba_premultiplied(255, 255, 255, 58),
                accent: Color32::from_rgb(162, 214, 255),
                accent_soft: Color32::from_rgba_premultiplied(162, 214, 255, 56),
                text_primary: Color32::from_rgb(246, 249, 255),
                text_secondary: Color32::from_rgb(202, 214, 232),
                text_muted: Color32::from_rgb(147, 160, 181),
                success: Color32::from_rgb(144, 221, 193),
                warning: Color32::from_rgb(240, 203, 132),
                danger: Color32::from_rgb(244, 142, 159),
                shadow: Color32::from_rgba_premultiplied(7, 15, 33, 88),
                terminal_bg: Color32::from_rgba_premultiplied(8, 12, 26, 236),
                terminal_border: Color32::from_rgba_premultiplied(126, 156, 198, 58),
                terminal_text: Color32::from_rgb(128, 231, 178),
            },
            ThemePreset::Celadon => Self {
                background_top: Color32::from_rgb(19, 40, 41),
                background_bottom: Color32::from_rgb(8, 18, 21),
                mist: Color32::from_rgba_premultiplied(255, 255, 255, 24),
                blossom: Color32::from_rgba_premultiplied(138, 225, 204, 40),
                panel: Color32::from_rgba_premultiplied(15, 34, 34, 122),
                panel_soft: Color32::from_rgba_premultiplied(22, 43, 44, 108),
                panel_alt: Color32::from_rgba_premultiplied(31, 57, 58, 144),
                stroke: Color32::from_rgba_premultiplied(245, 255, 251, 56),
                accent: Color32::from_rgb(152, 223, 206),
                accent_soft: Color32::from_rgba_premultiplied(152, 223, 206, 52),
                text_primary: Color32::from_rgb(242, 250, 247),
                text_secondary: Color32::from_rgb(198, 218, 212),
                text_muted: Color32::from_rgb(143, 164, 159),
                success: Color32::from_rgb(143, 218, 175),
                warning: Color32::from_rgb(237, 206, 138),
                danger: Color32::from_rgb(237, 146, 145),
                shadow: Color32::from_rgba_premultiplied(6, 18, 19, 84),
                terminal_bg: Color32::from_rgba_premultiplied(8, 12, 24, 236),
                terminal_border: Color32::from_rgba_premultiplied(110, 170, 154, 56),
                terminal_text: Color32::from_rgb(125, 231, 180),
            },
            ThemePreset::Vermilion => Self {
                background_top: Color32::from_rgb(47, 34, 29),
                background_bottom: Color32::from_rgb(18, 12, 11),
                mist: Color32::from_rgba_premultiplied(255, 250, 244, 24),
                blossom: Color32::from_rgba_premultiplied(255, 198, 145, 38),
                panel: Color32::from_rgba_premultiplied(45, 30, 24, 120),
                panel_soft: Color32::from_rgba_premultiplied(56, 39, 31, 106),
                panel_alt: Color32::from_rgba_premultiplied(72, 50, 40, 142),
                stroke: Color32::from_rgba_premultiplied(255, 248, 240, 56),
                accent: Color32::from_rgb(245, 204, 154),
                accent_soft: Color32::from_rgba_premultiplied(245, 204, 154, 52),
                text_primary: Color32::from_rgb(249, 245, 240),
                text_secondary: Color32::from_rgb(220, 205, 193),
                text_muted: Color32::from_rgb(167, 152, 141),
                success: Color32::from_rgb(151, 213, 176),
                warning: Color32::from_rgb(244, 206, 135),
                danger: Color32::from_rgb(244, 145, 130),
                shadow: Color32::from_rgba_premultiplied(24, 14, 10, 82),
                terminal_bg: Color32::from_rgba_premultiplied(10, 12, 24, 236),
                terminal_border: Color32::from_rgba_premultiplied(162, 147, 128, 58),
                terminal_text: Color32::from_rgb(131, 227, 179),
            },
        }
    }
}

pub struct App {
    servers: Vec<Server>,
    tabs: Vec<Tab>,
    active_tab: usize,
    search_query: String,
    runtime: Arc<Runtime>,
    server_form: ServerForm,
    flash_message: Option<FlashMessage>,
    toasts: Toasts,
    connection_history: Vec<ConnectionHistory>,
    command_history: Vec<CommandHistory>,
    shortcuts: Vec<ShortcutCommand>,
    scripts: Vec<Script>,
    next_tab_id: usize,
    settings: AppSettings,
    sync_form: SyncForm,
    script_form: ScriptForm,
    logged_in_user: Option<String>,
    editing_server_key: Option<String>,
    editing_script_name: Option<String>,
    show_sync_dialog: bool,
    show_server_editor_dialog: bool,
    auth_prompt_dialog: Option<AuthPromptDialog>,
    pending_delete_server: Option<Server>,
    app_page: AppPage,
    terminal_workbench_tab: TerminalWorkbenchTab,
    home_page: HomePage,
    resource_tab: ResourceTab,
    file_transfer: FileTransferPanel,
    file_transfer_tx: UnboundedSender<FileTransferEvent>,
    file_transfer_events: UnboundedReceiver<FileTransferEvent>,
    workspace_path: String,
    audit_entries: Vec<String>,
    terminal_focus_tab_id: Option<usize>,
    has_display_font: bool,
    background_texture: Option<egui::TextureHandle>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, servers: Vec<Server>) -> Self {
        let settings = load_settings();
        let has_display_font = install_fonts(&cc.egui_ctx);
        apply_theme(&cc.egui_ctx, settings.theme_preset);
        let (file_transfer_tx, file_transfer_events) = unbounded_channel();
        let background_texture = load_background_texture(&cc.egui_ctx);

        Self {
            servers,
            tabs: vec![],
            active_tab: 0,
            search_query: String::new(),
            runtime: Arc::new(Runtime::new().unwrap()),
            server_form: ServerForm::default(),
            flash_message: None,
            toasts: Toasts::new()
                .with_anchor(ToastAnchor::TopRight)
                .with_margin(vec2(18.0, 18.0))
                .with_spacing(10.0)
                .with_padding(vec2(12.0, 10.0))
                .with_default_font(FontId::new(14.0, FontFamily::Proportional))
                .with_shadow(Shadow {
                    offset: [0, 12],
                    blur: 30,
                    spread: 0,
                    color: Color32::from_rgba_premultiplied(0, 0, 0, 110),
                }),
            connection_history: load_connection_history(),
            command_history: load_command_history(),
            shortcuts: load_shortcuts(),
            scripts: load_scripts(),
            next_tab_id: 1,
            sync_form: SyncForm {
                username: settings.last_sync_user.clone().unwrap_or_default(),
                password: String::new(),
            },
            script_form: ScriptForm::default(),
            logged_in_user: None,
            editing_server_key: None,
            editing_script_name: None,
            show_sync_dialog: false,
            show_server_editor_dialog: false,
            auth_prompt_dialog: None,
            pending_delete_server: None,
            app_page: AppPage::Connections,
            terminal_workbench_tab: TerminalWorkbenchTab::SplitTerminal,
            home_page: HomePage::Hosts,
            resource_tab: ResourceTab::Commands,
            file_transfer: FileTransferPanel::new(),
            file_transfer_tx,
            file_transfer_events,
            workspace_path: default_workspace_path().display().to_string(),
            audit_entries: load_recent_audit_entries(24),
            terminal_focus_tab_id: None,
            has_display_font,
            background_texture,
            settings,
        }
    }

    fn palette(&self) -> ThemePalette {
        ThemePalette::from_preset(self.settings.theme_preset)
    }

    fn is_first_run(&self) -> bool {
        self.servers.is_empty()
            && self.tabs.is_empty()
            && self.connection_history.is_empty()
            && self.command_history.is_empty()
            && self.shortcuts.is_empty()
            && self.scripts.is_empty()
    }

    fn display_font(&self, size: f32) -> FontId {
        if self.has_display_font {
            FontId::new(size, FontFamily::Name(DISPLAY_FONT_NAME.into()))
        } else {
            FontId::new(size, FontFamily::Proportional)
        }
    }

    fn set_flash(&mut self, text: impl Into<String>, is_error: bool) {
        let text = text.into();
        self.flash_message = None;

        let toast = if is_error {
            self.toasts.error(text)
        } else {
            self.toasts.success(text)
        };
        toast
            .duration(Some(Duration::from_secs(if is_error { 6 } else { 4 })))
            .closable(true)
            .show_progress_bar(false)
            .width(320.0)
            .height(44.0);
    }

    fn persist_settings(&self) {
        save_settings(&self.settings);
    }

    fn persist_servers(&self) {
        save_servers(&self.servers);
    }

    fn open_sync_dialog(&mut self) {
        self.show_sync_dialog = true;
    }

    fn open_new_server_dialog(&mut self) {
        self.server_form.reset();
        self.editing_server_key = None;
        self.show_server_editor_dialog = true;
    }

    fn close_server_editor_dialog(&mut self) {
        self.show_server_editor_dialog = false;
        self.editing_server_key = None;
        self.server_form.reset();
    }

    fn request_server_delete(&mut self, server: Server) {
        self.pending_delete_server = Some(server);
    }

    fn clear_auth_prompt_for_tab(&mut self, tab_id: usize) {
        if self
            .auth_prompt_dialog
            .as_ref()
            .is_some_and(|dialog| dialog.tab_id == tab_id)
        {
            self.auth_prompt_dialog = None;
        }
    }

    fn has_modal_open(&self) -> bool {
        self.show_sync_dialog
            || self.show_server_editor_dialog
            || self.auth_prompt_dialog.is_some()
            || self.pending_delete_server.is_some()
    }

    fn has_blocking_modal_open(&self) -> bool {
        self.auth_prompt_dialog.is_some() || self.pending_delete_server.is_some()
    }

    fn sort_servers(&mut self) {
        self.servers.sort_by(|left, right| {
            left.group_name()
                .to_lowercase()
                .cmp(&right.group_name().to_lowercase())
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
                .then_with(|| left.host.to_lowercase().cmp(&right.host.to_lowercase()))
        });
    }

    fn sync_snapshot(&self) -> SyncSnapshot {
        SyncSnapshot {
            theme_preset: self.settings.theme_preset,
            servers: self.servers.clone(),
            connection_history: self.connection_history.clone(),
            command_history: self.command_history.clone(),
            shortcuts: self.shortcuts.clone(),
            scripts: self.scripts.clone(),
            synced_at: 0,
        }
    }

    fn auto_sync_if_logged_in(&mut self) {
        let Some(username) = self.logged_in_user.clone() else {
            return;
        };

        if let Err(error) = push_snapshot(&username, self.sync_snapshot()) {
            self.set_flash(format!("自动同步失败: {error:#}"), true);
        }
    }

    fn update_theme(&mut self, ctx: &egui::Context, preset: ThemePreset) {
        if self.settings.theme_preset == preset {
            return;
        }

        self.settings.theme_preset = preset;
        self.persist_settings();
        apply_theme(ctx, self.settings.theme_preset);
        self.auto_sync_if_logged_in();
        self.set_flash(
            format!("主题已切换为 {}。", self.settings.theme_preset.label()),
            false,
        );
    }

    fn login_sync_account(&mut self, ctx: &egui::Context) {
        let username = self.sync_form.username.trim().to_lowercase();
        let snapshot = self.sync_snapshot();

        match authenticate_or_create_account(&username, &self.sync_form.password, snapshot) {
            Ok(LoginOutcome::Created) => {
                self.logged_in_user = Some(username.clone());
                self.settings.last_sync_user = Some(username.clone());
                self.persist_settings();
                self.sync_form.password.clear();
                self.set_flash(format!("同步账号 `{username}` 已创建并完成初始化。"), false);
            }
            Ok(LoginOutcome::Existing) => {
                self.logged_in_user = Some(username.clone());
                self.settings.last_sync_user = Some(username.clone());
                self.persist_settings();
                self.sync_form.password.clear();

                if self.settings.auto_sync_on_login {
                    self.pull_from_sync_account(ctx);
                } else {
                    self.set_flash(
                        format!("已登录 `{username}`，现在可以拉取同步快照。"),
                        false,
                    );
                }
            }
            Err(error) => self.set_flash(format!("同步登录失败: {error:#}"), true),
        }
    }

    fn logout_sync_account(&mut self) {
        self.logged_in_user = None;
        self.sync_form.password.clear();
        self.set_flash("已退出同步登录。", false);
    }

    fn push_to_sync_account(&mut self) {
        let Some(username) = self.logged_in_user.clone() else {
            self.set_flash("请先登录同步账号，再推送快照。", true);
            return;
        };

        match push_snapshot(&username, self.sync_snapshot()) {
            Ok(()) => self.set_flash(
                format!("已将服务器、主题、历史、快捷命令和脚本推送到 `{username}`。"),
                false,
            ),
            Err(error) => self.set_flash(format!("同步推送失败: {error:#}"), true),
        }
    }

    fn pull_from_sync_account(&mut self, ctx: &egui::Context) {
        let Some(username) = self.logged_in_user.clone() else {
            self.set_flash("请先登录同步账号，再拉取快照。", true);
            return;
        };

        match pull_snapshot(&username) {
            Ok(Some(snapshot)) => {
                self.apply_sync_snapshot(ctx, snapshot);
                self.set_flash(format!("已从 `{username}` 拉取最新快照。"), false);
            }
            Ok(None) => self.set_flash("这个同步账号还没有保存过快照。", true),
            Err(error) => self.set_flash(format!("同步拉取失败: {error:#}"), true),
        }
    }

    fn apply_sync_snapshot(&mut self, ctx: &egui::Context, snapshot: SyncSnapshot) {
        // Import/sync uses the same restore path so the UI behaves the same regardless of source.
        self.servers = snapshot.servers;
        self.connection_history = snapshot.connection_history;
        self.command_history = snapshot.command_history;
        self.shortcuts = snapshot.shortcuts;
        self.scripts = snapshot.scripts;
        self.sort_servers();
        self.persist_servers();
        save_connection_history(&self.connection_history);
        save_command_history(&self.command_history);
        save_shortcuts(&self.shortcuts);
        save_scripts(&self.scripts);

        self.settings.theme_preset = snapshot.theme_preset;
        self.persist_settings();
        apply_theme(ctx, self.settings.theme_preset);
    }

    fn command_history_for_host(&self, host: &str) -> Vec<String> {
        let mut commands = Vec::new();
        for item in &self.command_history {
            if item.host == host && !commands.iter().any(|existing| existing == &item.command) {
                commands.push(item.command.clone());
            }
            if commands.len() >= HISTORY_LIMIT {
                break;
            }
        }
        commands
    }

    fn grouped_connection_history(&self) -> Vec<(String, Vec<ConnectionHistory>)> {
        let mut grouped: BTreeMap<String, Vec<ConnectionHistory>> = BTreeMap::new();
        for entry in &self.connection_history {
            let group = if entry.server_group.trim().is_empty() {
                DEFAULT_GROUP_NAME.to_string()
            } else {
                entry.server_group.clone()
            };
            grouped.entry(group).or_default().push(entry.clone());
        }

        let mut groups: Vec<(String, Vec<ConnectionHistory>)> = grouped.into_iter().collect();
        for (_, entries) in &mut groups {
            // Keep each group newest-first so the collapsed headers surface the latest activity.
            entries.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        }

        // Groups themselves are sorted by the latest item they contain, not alphabetically.
        groups.sort_by(|left, right| {
            let right_ts = right
                .1
                .first()
                .map(|entry| entry.timestamp)
                .unwrap_or_default();
            let left_ts = left
                .1
                .first()
                .map(|entry| entry.timestamp)
                .unwrap_or_default();
            right_ts.cmp(&left_ts).then_with(|| left.0.cmp(&right.0))
        });

        groups
    }

    fn server_for_history(&self, entry: &ConnectionHistory) -> Option<Server> {
        self.servers
            .iter()
            .find(|server| server.server_key() == entry.server_key)
            .cloned()
            .or_else(|| {
                // Older history records may not have a stable key, so fall back to endpoint matching.
                self.servers
                    .iter()
                    .find(|server| {
                        server.host.eq_ignore_ascii_case(&entry.host)
                            && server.port == entry.port
                            && server.user.eq_ignore_ascii_case(&entry.user)
                    })
                    .cloned()
            })
    }

    fn record_connection(&mut self, server: &Server) {
        // We keep one "latest touch" per endpoint so the history panel stays compact and useful.
        self.connection_history
            .retain(|entry| entry.server_key != server.server_key());
        self.connection_history
            .insert(0, ConnectionHistory::from_server(server));
        self.connection_history.truncate(100);
        save_connection_history(&self.connection_history);
        self.auto_sync_if_logged_in();
    }

    fn record_command(&mut self, command: &str, host: &str) {
        self.command_history
            .retain(|entry| !(entry.host == host && entry.command == command));
        self.command_history.insert(
            0,
            CommandHistory::new(command.to_string(), host.to_string()),
        );
        self.command_history.truncate(200);
        save_command_history(&self.command_history);
        self.auto_sync_if_logged_in();

        if let Some(server) = self
            .tabs
            .get(self.active_tab)
            .map(|tab| tab.server.clone())
            .filter(|server| server.host == host)
        {
            append_command_event(&server, command);
        }

        self.refresh_audit_entries();
    }

    fn pin_command_as_shortcut(&mut self, command: &str) {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            self.set_flash("请先输入命令，再进行收藏。", true);
            return;
        }

        if self
            .shortcuts
            .iter()
            .any(|shortcut| shortcut.command == trimmed)
        {
            self.set_flash("这条命令已经收藏过了。", true);
            return;
        }

        let name = shortcut_title(trimmed);
        self.shortcuts.push(ShortcutCommand::new(
            name.clone(),
            trimmed.to_string(),
            "从命令输入框收藏。".to_string(),
        ));
        save_shortcuts(&self.shortcuts);
        self.auto_sync_if_logged_in();
        self.set_flash(format!("已将 `{name}` 保存到快捷命令。"), false);
    }

    fn remove_shortcut(&mut self, index: usize) {
        if index >= self.shortcuts.len() {
            return;
        }
        let removed = self.shortcuts.remove(index);
        save_shortcuts(&self.shortcuts);
        self.auto_sync_if_logged_in();
        self.set_flash(format!("已移除快捷命令 `{}`。", removed.name), false);
    }

    fn save_script_from_form(&mut self) {
        let name = self.script_form.name.trim();
        let content = self.script_form.content.trim();

        if name.is_empty() {
            self.set_flash("脚本名称不能为空。", true);
            return;
        }
        if content.is_empty() {
            self.set_flash("脚本内容不能为空。", true);
            return;
        }

        if let Some(existing_name) = self.editing_script_name.clone() {
            if existing_name != name && self.scripts.iter().any(|script| script.name == name) {
                self.set_flash("同名脚本已经存在。", true);
                return;
            }

            if let Some(script) = self
                .scripts
                .iter_mut()
                .find(|script| script.name == existing_name)
            {
                // Updates keep the script identity in-place so sync/export order remains stable.
                script.name = name.to_string();
                script.description = self.script_form.description.trim().to_string();
                script.content = content.to_string();
                script.updated_at = current_timestamp();
                save_scripts(&self.scripts);
                self.auto_sync_if_logged_in();
                self.script_form.reset();
                self.editing_script_name = None;
                self.set_flash("脚本已更新。", false);
                return;
            }
        }

        if self.scripts.iter().any(|script| script.name == name) {
            self.set_flash("同名脚本已经存在。", true);
            return;
        }

        let now = current_timestamp();
        self.scripts.push(Script {
            name: name.to_string(),
            description: self.script_form.description.trim().to_string(),
            content: content.to_string(),
            created_at: now,
            updated_at: now,
        });
        self.scripts
            .sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        save_scripts(&self.scripts);
        self.auto_sync_if_logged_in();
        self.script_form.reset();
        self.set_flash("脚本已保存。", false);
    }

    fn remove_script(&mut self, name: &str) {
        let before = self.scripts.len();
        self.scripts.retain(|script| script.name != name);
        if self.scripts.len() == before {
            return;
        }
        save_scripts(&self.scripts);
        self.auto_sync_if_logged_in();
        if self.editing_script_name.as_deref() == Some(name) {
            self.editing_script_name = None;
            self.script_form.reset();
        }
        self.set_flash(format!("已删除脚本 `{name}`。"), false);
    }

    fn start_editing_script(&mut self, script: &Script) {
        self.script_form.fill_from_script(script);
        self.editing_script_name = Some(script.name.clone());
    }

    fn export_workspace_snapshot(&mut self) {
        let path = PathBuf::from(self.workspace_path.trim());
        if self.workspace_path.trim().is_empty() {
            self.set_flash("工作区导出路径不能为空。", true);
            return;
        }

        if let Some(parent) = path.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                self.set_flash(format!("创建导出目录失败: {error}"), true);
                return;
            }
        }

        // Export reuses the sync snapshot schema so local backups and sync stay compatible.
        match serde_json::to_string_pretty(&self.sync_snapshot()) {
            Ok(payload) => match fs::write(&path, payload) {
                Ok(()) => self.set_flash(format!("工作区已导出到 `{}`。", path.display()), false),
                Err(error) => self.set_flash(format!("导出工作区失败: {error}"), true),
            },
            Err(error) => self.set_flash(format!("序列化工作区失败: {error}"), true),
        }
    }

    fn import_workspace_snapshot(&mut self, ctx: &egui::Context) {
        let path = PathBuf::from(self.workspace_path.trim());
        if self.workspace_path.trim().is_empty() {
            self.set_flash("工作区导入路径不能为空。", true);
            return;
        }

        let payload = match fs::read_to_string(&path) {
            Ok(payload) => payload,
            Err(error) => {
                self.set_flash(format!("读取工作区快照失败: {error}"), true);
                return;
            }
        };

        // Import is intentionally strict here so a broken snapshot never partially mutates state.
        match serde_json::from_str::<SyncSnapshot>(&payload) {
            Ok(snapshot) => {
                self.apply_sync_snapshot(ctx, snapshot);
                self.set_flash(format!("工作区已从 `{}` 导入。", path.display()), false);
            }
            Err(error) => self.set_flash(format!("解析工作区快照失败: {error}"), true),
        }
    }

    fn refresh_audit_entries(&mut self) {
        self.audit_entries = load_recent_audit_entries(24);
    }

    fn request_file_list(&mut self, server: Server, path: Option<String>) {
        let path = path.unwrap_or_else(|| self.file_transfer.remote_path.trim().to_string());
        let tx = self.file_transfer_tx.clone();
        self.file_transfer.busy_label = Some("正在读取远端目录...".to_string());
        self.file_transfer.status_text = format!("正在读取 {} 的远端目录...", server.endpoint());

        self.runtime.spawn(async move {
            let result = sftp_list_dir(server.clone(), path).await;
            let event = match result {
                Ok((path, entries)) => FileTransferEvent::DirectoryLoaded {
                    server,
                    path,
                    entries,
                },
                Err(error) => FileTransferEvent::Error {
                    server: Some(server),
                    message: format!("读取远端目录失败：{error:#}"),
                },
            };
            let _ = tx.send(event);
        });
    }

    fn request_file_download(&mut self, server: Server, remote_path: String, local_path: PathBuf) {
        let tx = self.file_transfer_tx.clone();
        self.file_transfer.busy_label = Some("正在下载文件...".to_string());
        self.file_transfer.status_text = format!(
            "正在从 {} 下载文件到 {}...",
            server.endpoint(),
            local_path.display()
        );

        self.runtime.spawn(async move {
            let result =
                sftp_download_file(server.clone(), remote_path.clone(), local_path.clone()).await;
            let event = match result {
                Ok(saved_path) => FileTransferEvent::Downloaded {
                    server,
                    remote_path,
                    local_path: saved_path,
                },
                Err(error) => FileTransferEvent::Error {
                    server: Some(server),
                    message: format!("下载文件失败：{error:#}"),
                },
            };
            let _ = tx.send(event);
        });
    }

    fn request_file_upload(&mut self, server: Server, local_path: PathBuf, remote_path: String) {
        let tx = self.file_transfer_tx.clone();
        self.file_transfer.busy_label = Some("正在上传文件...".to_string());
        self.file_transfer.status_text =
            format!("正在把 {} 上传到 {}...", local_path.display(), remote_path);

        self.runtime.spawn(async move {
            let result =
                sftp_upload_file(server.clone(), local_path.clone(), remote_path.clone()).await;
            let event = match result {
                Ok(remote_path) => FileTransferEvent::Uploaded {
                    server,
                    remote_path,
                    local_path,
                },
                Err(error) => FileTransferEvent::Error {
                    server: Some(server),
                    message: format!("上传文件失败：{error:#}"),
                },
            };
            let _ = tx.send(event);
        });
    }

    fn request_create_remote_dir(&mut self, server: Server, path: String) {
        let tx = self.file_transfer_tx.clone();
        self.file_transfer.busy_label = Some("正在创建目录...".to_string());
        self.file_transfer.status_text = format!("正在创建远端目录：{path}");

        self.runtime.spawn(async move {
            let result = sftp_create_dir(server.clone(), path.clone()).await;
            let event = match result {
                Ok(path) => FileTransferEvent::DirectoryCreated { server, path },
                Err(error) => FileTransferEvent::Error {
                    server: Some(server),
                    message: format!("创建远端目录失败：{error:#}"),
                },
            };
            let _ = tx.send(event);
        });
    }

    fn request_remove_remote_path(&mut self, server: Server, path: String, is_dir: bool) {
        let tx = self.file_transfer_tx.clone();
        self.file_transfer.busy_label = Some("正在删除远端项目...".to_string());
        self.file_transfer.status_text = format!("正在删除远端项目：{path}");

        self.runtime.spawn(async move {
            let result = sftp_remove_path(server.clone(), path.clone(), is_dir).await;
            let event = match result {
                Ok(path) => FileTransferEvent::Removed {
                    server,
                    path,
                    is_dir,
                },
                Err(error) => FileTransferEvent::Error {
                    server: Some(server),
                    message: format!("删除远端项目失败：{error:#}"),
                },
            };
            let _ = tx.send(event);
        });
    }

    fn resolve_download_target(&self, entry: &RemoteFileEntry) -> Result<PathBuf> {
        let raw = self.file_transfer.local_path.trim();
        if raw.is_empty() {
            bail!("请先填写本地路径。");
        }

        let mut local_path = PathBuf::from(raw);
        let looks_like_directory = raw.ends_with('/') || raw.ends_with('\\');
        if local_path.is_dir() || looks_like_directory {
            local_path = local_path.join(&entry.name);
        }

        Ok(local_path)
    }

    fn resolve_upload_target(&self) -> Result<(PathBuf, String)> {
        let raw = self.file_transfer.local_path.trim();
        if raw.is_empty() {
            bail!("请先填写本地文件路径。");
        }

        let local_path = PathBuf::from(raw);
        if !local_path.exists() {
            bail!("本地文件不存在：{}", local_path.display());
        }
        if !local_path.is_file() {
            bail!("上传时本地路径必须是一个文件：{}", local_path.display());
        }

        let remote_name = sftp_local_file_name(&local_path)?;
        let remote_path = join_sftp_path(self.file_transfer.remote_path.trim(), &remote_name);
        Ok((local_path, remote_path))
    }

    fn poll_file_transfer_events(&mut self) {
        loop {
            let event = match self.file_transfer_events.try_recv() {
                Ok(event) => event,
                Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
            };
            self.apply_file_transfer_event(event);
        }
    }

    fn apply_file_transfer_event(&mut self, event: FileTransferEvent) {
        match event {
            FileTransferEvent::DirectoryLoaded {
                server,
                path,
                entries,
            } => {
                if self.file_transfer.server_key.as_deref() == Some(server.server_key().as_str()) {
                    self.file_transfer.remote_path = path.clone();
                    self.file_transfer.entries = entries;
                    self.file_transfer.selected_remote_path = None;
                    self.file_transfer.status_text = format!(
                        "已加载 {}，共 {} 项。",
                        path,
                        self.file_transfer.entries.len()
                    );
                    self.file_transfer.busy_label = None;
                }
            }
            FileTransferEvent::Downloaded {
                server,
                remote_path,
                local_path,
            } => {
                self.file_transfer.busy_label = None;
                self.file_transfer.status_text = format!("已下载到 {}", local_path.display());
                self.set_flash(
                    format!("已将 `{remote_path}` 下载到 `{}`。", local_path.display()),
                    false,
                );
                append_server_event(
                    &server,
                    "文件下载",
                    &format!("remote={remote_path} local={}", local_path.display()),
                );
                self.refresh_audit_entries();
            }
            FileTransferEvent::Uploaded {
                server,
                remote_path,
                local_path,
            } => {
                self.file_transfer.busy_label = None;
                self.file_transfer.status_text = format!("已上传到 {remote_path}");
                self.set_flash(
                    format!("已把 `{}` 上传到 `{remote_path}`。", local_path.display()),
                    false,
                );
                append_server_event(
                    &server,
                    "文件上传",
                    &format!("local={} remote={remote_path}", local_path.display()),
                );
                self.refresh_audit_entries();
                self.request_file_list(server, Some(self.file_transfer.remote_path.clone()));
            }
            FileTransferEvent::DirectoryCreated { server, path } => {
                self.file_transfer.busy_label = None;
                self.file_transfer.new_directory_name.clear();
                self.file_transfer.status_text = format!("已创建目录：{path}");
                self.set_flash(format!("已创建远端目录 `{path}`。"), false);
                append_server_event(&server, "创建目录", &format!("path={path}"));
                self.refresh_audit_entries();
                self.request_file_list(server, Some(self.file_transfer.remote_path.clone()));
            }
            FileTransferEvent::Removed {
                server,
                path,
                is_dir,
            } => {
                self.file_transfer.busy_label = None;
                self.file_transfer.selected_remote_path = None;
                self.file_transfer.status_text = format!("已删除：{path}");
                self.set_flash(
                    format!(
                        "已删除远端{} `{path}`。",
                        if is_dir { "目录" } else { "文件" }
                    ),
                    false,
                );
                append_server_event(
                    &server,
                    if is_dir {
                        "删除目录"
                    } else {
                        "删除文件"
                    },
                    &format!("path={path}"),
                );
                self.refresh_audit_entries();
                self.request_file_list(server, Some(self.file_transfer.remote_path.clone()));
            }
            FileTransferEvent::Error { server, message } => {
                self.file_transfer.busy_label = None;
                self.file_transfer.status_text = message.clone();
                self.set_flash(message.clone(), true);
                if let Some(server) = server {
                    append_server_event(&server, "文件传输错误", &message);
                    self.refresh_audit_entries();
                }
            }
        }
    }

    fn add_or_update_server_from_form(&mut self) {
        match self.server_form.build_server() {
            Ok(mut server) => {
                let editing_key = self.editing_server_key.clone();
                let existing_server = editing_key.as_ref().and_then(|key| {
                    self.servers
                        .iter()
                        .find(|existing| existing.server_key() == *key)
                        .cloned()
                });

                let duplicate = self
                    .servers
                    .iter()
                    .filter(|existing| {
                        Some(existing.server_key())
                            != existing_server.as_ref().map(Server::server_key)
                    })
                    .any(|existing| {
                        existing.host.eq_ignore_ascii_case(&server.host)
                            && existing.port == server.port
                            && existing.user.eq_ignore_ascii_case(&server.user)
                    });
                if duplicate {
                    self.set_flash("这个服务器条目已经存在。", true);
                    return;
                }

                if let Some(existing) = &existing_server {
                    if server.auth_method == AuthMethod::Password
                        && server.password.is_none()
                        && existing.auth_method == AuthMethod::Password
                        && existing.password_in_keyring
                    {
                        server.password_in_keyring = true;
                    }
                }

                if server.auth_method == AuthMethod::Password {
                    if let Some(password) = server.password.clone() {
                        match store_server_password(&server, &password) {
                            Ok(()) => {
                                server.password = None;
                                server.password_in_keyring = true;
                            }
                            Err(error) => {
                                self.set_flash(format!("安全保存密码失败: {error:#}"), true);
                                return;
                            }
                        }
                    }
                }

                let updated = if let Some(key) = editing_key {
                    if let Some(index) = self
                        .servers
                        .iter()
                        .position(|existing| existing.server_key() == key)
                    {
                        self.servers[index] = server;
                        true
                    } else {
                        self.servers.push(server);
                        false
                    }
                } else {
                    self.servers.push(server);
                    false
                };

                self.sort_servers();
                self.persist_servers();
                self.auto_sync_if_logged_in();
                self.refresh_audit_entries();
                self.close_server_editor_dialog();
                self.set_flash(
                    if updated {
                        "服务器已更新，并完成安全凭据处理。".to_string()
                    } else {
                        "服务器已保存，并完成安全凭据处理。".to_string()
                    },
                    false,
                );
            }
            Err(error) => self.set_flash(error.to_string(), true),
        }
    }

    fn delete_server(&mut self, server_key: &str) {
        if let Some(index) = self
            .servers
            .iter()
            .position(|server| server.server_key() == server_key)
        {
            let server = self.servers.remove(index);
            self.persist_servers();
            self.auto_sync_if_logged_in();
            self.refresh_audit_entries();
            if self.editing_server_key.as_deref() == Some(server_key) {
                self.close_server_editor_dialog();
            }
            self.pending_delete_server = None;
            self.set_flash(format!("已删除已保存的服务器 `{}`。", server.name), false);
        }
    }

    fn start_editing_server(&mut self, server: &Server) {
        self.server_form.fill_from_server(server);
        self.editing_server_key = Some(server.server_key());
        self.show_server_editor_dialog = true;
    }

    fn prefill_from_history(&mut self, entry: &ConnectionHistory) {
        self.server_form.fill_from_history(entry);
        self.editing_server_key = None;
        self.show_server_editor_dialog = true;
        self.set_flash(
            format!("已将 `{}` 回填到服务器编辑器。", entry.server_name),
            false,
        );
    }

    fn restart_tab_session(&mut self, index: usize) {
        if index >= self.tabs.len() {
            return;
        }

        let server = self.tabs[index].server.clone();
        let ManagedSession { handle, events } = connect_ssh(self.runtime.clone(), server.clone());
        self.record_connection(&server);
        self.tabs[index].prepare_for_new_session(handle, events);
        self.active_tab = index;
        self.resource_tab = ResourceTab::Commands;
    }

    fn focus_existing_session_tab(&mut self, server_key: &str) -> bool {
        let Some(index) = self
            .tabs
            .iter()
            .rposition(|tab| tab.server.server_key() == server_key)
        else {
            return false;
        };

        self.active_tab = index;
        self.tabs[index].unseen_output = false;
        true
    }

    fn open_session_tab(&mut self, server: Server) {
        let ManagedSession { handle, events } = connect_ssh(self.runtime.clone(), server.clone());
        self.record_connection(&server);

        let tab = Tab::new(self.next_tab_id, server, handle, events);
        self.next_tab_id += 1;
        self.tabs.push(tab);
        self.active_tab = self.tabs.len().saturating_sub(1);
        self.resource_tab = ResourceTab::Commands;
        self.app_page = AppPage::Terminal;
    }

    #[allow(unreachable_code)]
    fn connect_to_server(&mut self, server: Server) {
        self.home_page = HomePage::Hosts;
        self.open_session_tab(server.clone());
        return;
        let existing_tab = self
            .tabs
            .iter()
            .position(|tab| tab.server.server_key() == server.server_key());

        if let Some(index) = existing_tab {
            self.active_tab = index;
            self.tabs[index].unseen_output = false;

            match self.tabs[index].state {
                TabState::Disconnected | TabState::Failed => {
                    self.restart_tab_session(index);
                    self.set_flash("已重新打开现有会话标签页。", false);
                }
                TabState::Connecting | TabState::Reconnecting | TabState::Connected => {
                    self.set_flash("已切换到现有会话标签页。", false);
                }
            }
            return;
        }

        let ManagedSession { handle, events } = connect_ssh(self.runtime.clone(), server.clone());
        self.record_connection(&server);

        let tab = Tab::new(self.next_tab_id, server, handle, events);
        self.next_tab_id += 1;
        self.tabs.push(tab);
        self.active_tab = self.tabs.len().saturating_sub(1);
        self.resource_tab = ResourceTab::Commands;
    }

    fn close_tab(&mut self, index: usize) {
        if let Some(tab) = self.tabs.get(index) {
            let tab_id = tab.id;
            let session = tab.session.clone();
            self.clear_auth_prompt_for_tab(tab_id);
            let _ = session.disconnect();
        }
        if index < self.tabs.len() {
            let removed = self.tabs.remove(index);
            if self.terminal_focus_tab_id == Some(removed.id) {
                self.terminal_focus_tab_id = None;
            }
        }

        if self.tabs.is_empty() {
            self.active_tab = 0;
            self.home_page = HomePage::Hosts;
        } else if self.active_tab >= self.tabs.len() {
            self.active_tab = self.tabs.len() - 1;
        }
    }

    fn poll_sessions(&mut self) {
        for index in 0..self.tabs.len() {
            loop {
                let event = match self.tabs[index].events.try_recv() {
                    Ok(event) => event,
                    Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
                };
                self.apply_session_event(index, event);
            }
        }
    }

    fn apply_session_event(&mut self, index: usize, event: SessionEvent) {
        let is_active = index == self.active_tab;
        let tab = &mut self.tabs[index];
        let tab_id = tab.id;
        let mut pending_auth_prompt: Option<AuthPromptDialog> = None;
        let mut clear_auth_prompt = false;

        match event {
            SessionEvent::Status(message) => {
                tab.status_text = message.clone();
                tab.push_system_message(&message);
            }
            SessionEvent::Connected { message, attempt } => {
                tab.state = TabState::Connected;
                tab.connection_attempt = attempt;
                tab.reconnect_count = attempt.saturating_sub(1);
                tab.connected_at = Some(Instant::now());
                tab.retry_delay_secs = None;
                tab.status_text = message.clone();
                tab.push_system_message(&message);
                clear_auth_prompt = true;
            }
            SessionEvent::Retrying {
                message,
                attempt,
                delay_secs,
            } => {
                tab.state = TabState::Reconnecting;
                tab.connection_attempt = attempt;
                tab.connected_at = None;
                tab.retry_delay_secs = Some(delay_secs);
                tab.status_text = message.clone();
                tab.push_system_message(&message);
                clear_auth_prompt = true;
            }
            SessionEvent::Output(output) => {
                let text = terminal_text_from_bytes(&output);
                if !text.is_empty() {
                    tab.push_output(&text);
                }
                if !is_active && !output.is_empty() {
                    tab.unseen_output = true;
                }
            }
            SessionEvent::AuthPrompt {
                title,
                instructions,
                prompts,
            } => {
                tab.status_text = title.clone();
                if !instructions.trim().is_empty() {
                    tab.push_system_message(&instructions);
                }
                pending_auth_prompt = Some(AuthPromptDialog {
                    tab_id,
                    title,
                    instructions,
                    responses: vec![String::new(); prompts.len()],
                    prompts,
                });
            }
            SessionEvent::Error(message) => {
                tab.state = TabState::Failed;
                tab.connected_at = None;
                tab.retry_delay_secs = None;
                tab.status_text = message.clone();
                tab.push_system_message(&format!("错误: {message}"));
                clear_auth_prompt = true;
                if !is_active {
                    tab.unseen_output = true;
                }
            }
            SessionEvent::Disconnected(message) => {
                if tab.state != TabState::Failed {
                    tab.state = TabState::Disconnected;
                }
                tab.connected_at = None;
                tab.retry_delay_secs = None;
                tab.status_text = message.clone();
                tab.push_system_message(&message);
                clear_auth_prompt = true;
            }
        }

        if clear_auth_prompt {
            self.clear_auth_prompt_for_tab(tab_id);
        }
        if let Some(dialog) = pending_auth_prompt {
            self.auth_prompt_dialog = Some(dialog);
        }
    }

    fn send_active_command(&mut self, command: String) {
        if self.tabs.is_empty() {
            return;
        }

        let trimmed = command.trim();
        if trimmed.is_empty() {
            return;
        }

        let active_index = self.active_tab;
        let host = self.tabs[active_index].server.host.clone();
        let result = self.tabs[active_index]
            .session
            .send_input(format!("{trimmed}\n").into_bytes());

        match result {
            Ok(()) => {
                self.tabs[active_index].input_buffer.clear();
                self.tabs[active_index].history_cursor = None;
                self.record_command(trimmed, &host);
            }
            Err(error) => {
                let message = format!("发送命令失败: {error}");
                self.tabs[active_index].push_system_message(&message);
                self.set_flash(message, true);
            }
        }
    }

    fn send_terminal_bytes(&mut self, tab_index: usize, data: Vec<u8>) -> bool {
        if data.is_empty() || tab_index >= self.tabs.len() {
            return false;
        }

        match self.tabs[tab_index].session.send_input(data) {
            Ok(()) => {
                self.tabs[tab_index].auto_scroll = true;
                true
            }
            Err(error) => {
                let message = format!("发送终端输入失败: {error}");
                self.tabs[tab_index].push_system_message(&message);
                self.set_flash(message, true);
                false
            }
        }
    }

    fn push_tracked_terminal_text(&mut self, tab_index: usize, text: &str) {
        if let Some(tab) = self.tabs.get_mut(tab_index) {
            tab.history_cursor = None;
            tab.input_buffer.push_str(text);
        }
    }

    fn pop_tracked_terminal_text(&mut self, tab_index: usize) {
        if let Some(tab) = self.tabs.get_mut(tab_index) {
            tab.history_cursor = None;
            let _ = tab.input_buffer.pop();
        }
    }

    fn clear_tracked_terminal_text(&mut self, tab_index: usize) {
        if let Some(tab) = self.tabs.get_mut(tab_index) {
            tab.history_cursor = None;
            tab.input_buffer.clear();
        }
    }

    fn echo_terminal_interrupt(&mut self, tab_index: usize) {
        if let Some(tab) = self.tabs.get_mut(tab_index) {
            tab.history_cursor = None;
            tab.input_buffer.clear();
            tab.push_output("^C\n");
            tab.auto_scroll = true;
        }
    }

    fn commit_tracked_terminal_command(&mut self, tab_index: usize) {
        if tab_index >= self.tabs.len() {
            return;
        }

        let host = self.tabs[tab_index].server.host.clone();
        let command = self.tabs[tab_index].input_buffer.trim().to_string();
        self.tabs[tab_index].history_cursor = None;
        self.tabs[tab_index].input_buffer.clear();

        if !command.is_empty() {
            self.record_command(&command, &host);
        }
    }

    fn handle_terminal_input(&mut self, ctx: &egui::Context, tab_index: usize) {
        if !matches!(
            self.tabs.get(tab_index).map(|tab| tab.state),
            Some(TabState::Connected)
        ) {
            return;
        }

        let events = ctx.input(|input| input.events.clone());
        for event in events {
            match event {
                egui::Event::Text(text) => {
                    if text.chars().all(char::is_control) {
                        continue;
                    }

                    if self.send_terminal_bytes(tab_index, text.clone().into_bytes()) {
                        self.push_tracked_terminal_text(tab_index, &text);
                    }
                }
                egui::Event::Paste(text) => {
                    let normalized = text.replace("\r\n", "\n");
                    if self.send_terminal_bytes(tab_index, normalized.clone().into_bytes()) {
                        if normalized.contains('\n') || normalized.contains('\r') {
                            self.clear_tracked_terminal_text(tab_index);
                        } else {
                            self.push_tracked_terminal_text(tab_index, &normalized);
                        }
                    }
                }
                egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => {
                    if modifiers.mac_cmd {
                        continue;
                    }

                    let Some(bytes) = terminal_key_bytes(key, modifiers) else {
                        continue;
                    };

                    if !self.send_terminal_bytes(tab_index, bytes) {
                        continue;
                    }

                    if modifiers.ctrl && key == egui::Key::C {
                        self.echo_terminal_interrupt(tab_index);
                    }

                    match key {
                        egui::Key::Enter => self.commit_tracked_terminal_command(tab_index),
                        egui::Key::Backspace => self.pop_tracked_terminal_text(tab_index),
                        egui::Key::Tab if !modifiers.shift => {
                            self.push_tracked_terminal_text(tab_index, "\t");
                        }
                        egui::Key::ArrowUp
                        | egui::Key::ArrowDown
                        | egui::Key::ArrowLeft
                        | egui::Key::ArrowRight
                        | egui::Key::Home
                        | egui::Key::End
                        | egui::Key::PageUp
                        | egui::Key::PageDown
                        | egui::Key::Insert
                        | egui::Key::Delete
                        | egui::Key::Escape => self.clear_tracked_terminal_text(tab_index),
                        _ if modifiers.ctrl || modifiers.alt || modifiers.command => {
                            self.clear_tracked_terminal_text(tab_index);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    #[allow(dead_code)]
    fn draw_top_bar(&mut self, ctx: &egui::Context) {
        let palette = self.palette();
        egui::TopBottomPanel::top("top_bar")
            .resizable(false)
            .show(ctx, |ui| {
                card_frame(&palette, palette.panel, 14).show(ui, |ui| {
                    let connected_count = self
                        .tabs
                        .iter()
                        .filter(|tab| tab.state == TabState::Connected)
                        .count();
                    let recovering_count = self
                        .tabs
                        .iter()
                        .filter(|tab| {
                            matches!(tab.state, TabState::Connecting | TabState::Reconnecting)
                        })
                        .count();

                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("莓莓SSH终端")
                                .font(self.display_font(28.0))
                                .color(palette.text_primary),
                        );
                        ui.label(
                            RichText::new("更柔和的终端工作台，支持分组历史与同步。")
                                .small()
                                .color(palette.text_secondary),
                        );
                    });
                    ui.add_space(8.0);

                    ui.horizontal_wrapped(|ui| {
                        stat_chip(ui, &palette, "已保存", self.servers.len().to_string());
                        stat_chip(ui, &palette, "标签页", self.tabs.len().to_string());
                        stat_chip(ui, &palette, "在线", connected_count.to_string());
                        stat_chip(ui, &palette, "恢复中", recovering_count.to_string());

                        ui.add_space(12.0);
                        ui.label(
                            RichText::new("配色")
                                .small()
                                .strong()
                                .color(palette.text_secondary),
                        );

                        let mut selected_theme = self.settings.theme_preset;
                        egui::ComboBox::from_id_salt("theme_preset")
                            .selected_text(selected_theme.label())
                            .show_ui(ui, |ui| {
                                for preset in [
                                    ThemePreset::PeachBlossom,
                                    ThemePreset::Celadon,
                                    ThemePreset::Vermilion,
                                ] {
                                    ui.selectable_value(
                                        &mut selected_theme,
                                        preset,
                                        preset.label(),
                                    );
                                }
                            });
                        if selected_theme != self.settings.theme_preset {
                            self.update_theme(ctx, selected_theme);
                        }

                        ui.label(
                            RichText::new(self.settings.theme_preset.subtitle())
                                .small()
                                .color(palette.text_muted),
                        );
                    });

                    if let Some(message) = &self.flash_message {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("玻璃质感的 SSH 工作台")
                                    .small()
                                    .color(palette.text_muted),
                            );
                        });
                        ui.add_space(12.0);
                        let fill = if message.is_error {
                            palette.danger.linear_multiply(0.18)
                        } else {
                            palette.success.linear_multiply(0.18)
                        };
                        let stroke = if message.is_error {
                            palette.danger
                        } else {
                            palette.success
                        };
                        egui::Frame::new()
                            .fill(fill)
                            .stroke(Stroke::new(1.0, stroke))
                            .corner_radius(CornerRadius::same(14))
                            .inner_margin(Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(&message.text)
                                        .small()
                                        .color(palette.text_primary),
                                );
                            });
                    }
                });
            });
    }

    #[allow(dead_code)]
    fn draw_top_bar_compact(&mut self, ctx: &egui::Context) {
        let palette = self.palette();
        egui::TopBottomPanel::top("top_bar_compact")
            .resizable(false)
            .show(ctx, |ui| {
                card_frame(&palette, palette.panel, 12).show(ui, |ui| {
                    let connected_count = self
                        .tabs
                        .iter()
                        .filter(|tab| tab.state == TabState::Connected)
                        .count();

                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("莓莓SSH终端")
                                .font(self.display_font(26.0))
                                .color(palette.text_primary),
                        );
                        ui.label(
                            RichText::new("更干净的会话工作台")
                                .small()
                                .color(palette.text_secondary),
                        );

                        ui.add_space(10.0);
                        stat_chip(ui, &palette, "主机", self.servers.len().to_string());
                        stat_chip(ui, &palette, "标签", self.tabs.len().to_string());
                        stat_chip(ui, &palette, "在线", connected_count.to_string());

                        ui.add_space(10.0);
                        if ui.button("新建连接").clicked() {
                            self.open_new_server_dialog();
                        }
                        if ui.button("云同步").clicked() {
                            self.open_sync_dialog();
                        }
                        if ui.button("工作台").clicked() {
                            self.resource_tab = ResourceTab::Workspace;
                        }

                        ui.add_space(10.0);
                        let mut selected_theme = self.settings.theme_preset;
                        egui::ComboBox::from_id_salt("theme_preset_compact")
                            .selected_text(selected_theme.label())
                            .show_ui(ui, |ui| {
                                for preset in [
                                    ThemePreset::PeachBlossom,
                                    ThemePreset::Celadon,
                                    ThemePreset::Vermilion,
                                ] {
                                    ui.selectable_value(
                                        &mut selected_theme,
                                        preset,
                                        preset.label(),
                                    );
                                }
                            });
                        if selected_theme != self.settings.theme_preset {
                            self.update_theme(ctx, selected_theme);
                        }

                        let sync_status = self
                            .logged_in_user
                            .as_deref()
                            .map(|user| format!("已同步 {user}"))
                            .unwrap_or_else(|| "未登录同步".to_string());
                        badge(
                            ui,
                            &palette,
                            &sync_status,
                            palette.panel_alt,
                            palette.text_secondary,
                        );
                        });
                        ui.add_space(2.0);
                        ui.separator();
                });
            });
    }

    #[allow(dead_code)]
    fn draw_server_panel_clean(
        &mut self,
        ctx: &egui::Context,
        pending_connect: &mut Option<Server>,
    ) {
        let palette = self.palette();
        let servers: Vec<Server> = self
            .servers
            .iter()
            .filter(|server| server.matches_query(&self.search_query))
            .cloned()
            .collect();

        egui::SidePanel::left("servers_panel_clean")
            .resizable(false)
            .default_width(292.0)
            .min_width(292.0)
            .max_width(292.0)
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = vec2(10.0, 10.0);
                ui.label(
                    RichText::new("连接主机")
                        .font(self.display_font(22.0))
                        .color(palette.text_primary),
                );
                ui.add(
                    TextEdit::singleline(&mut self.search_query)
                        .hint_text("搜索主机")
                        .desired_width(f32::INFINITY),
                );
                if ui.button("新建连接").clicked() {
                    self.open_new_server_dialog();
                }
                ui.separator();

                if servers.is_empty() {
                    let message = if self.servers.is_empty() {
                        "还没有已保存的主机。"
                    } else {
                        "没有找到匹配的主机。"
                    };
                    ui.label(RichText::new(message).color(palette.text_secondary));
                    return;
                }

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for server in &servers {
                            let server = server.clone();
                            ui.horizontal_wrapped(|ui| {
                                if ui
                                    .selectable_label(
                                        false,
                                        RichText::new(&server.name)
                                            .strong()
                                            .color(palette.text_primary),
                                    )
                                    .clicked()
                                {
                                    *pending_connect = Some(server.clone());
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("连接").clicked() {
                                            *pending_connect = Some(server.clone());
                                        }
                                    },
                                );
                            });
                            ui.label(
                                RichText::new(server.endpoint())
                                    .small()
                                    .color(palette.text_secondary),
                            );
                            ui.separator();
                        }
                    });

                if false {
                card_frame(&palette, palette.panel_soft, 12).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new("连接主机")
                                .font(self.display_font(22.0))
                                .color(palette.text_primary),
                        );
                        ui.label(
                            RichText::new("把低频配置收起，主界面只保留主机库。")
                                .small()
                                .color(palette.text_secondary),
                        );
                    });
                    ui.separator();
                    ui.add(
                        TextEdit::singleline(&mut self.search_query)
                            .hint_text("搜索主机")
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(8.0);
                    if ui.button("新建连接").clicked() {
                        self.open_new_server_dialog();
                    }
                });

                if servers.is_empty() {
                    card_frame(&palette, palette.panel, 14).show(ui, |ui| {
                        let message = if self.servers.is_empty() {
                            "第一次进入时这里不再是空白，直接从“新建连接”开始即可。"
                        } else {
                            "没有找到匹配的主机，试试别的关键词。"
                        };
                        ui.label(RichText::new(message).color(palette.text_secondary));
                    });
                    return;
                }

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for server in &servers {
                            let server = server.clone();
                            card_frame(&palette, palette.panel, 10).show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(&server.name)
                                            .strong()
                                            .color(palette.text_primary),
                                    );
                                    if ui.button("连接").clicked() {
                                        *pending_connect = Some(server.clone());
                                    }
                                });
                                ui.label(
                                    RichText::new(server.endpoint())
                                        .small()
                                        .color(palette.text_secondary),
                                );
                            });
                            ui.add_space(8.0);
                        }
                    });
                }
            });
    }

    fn draw_terminal_shell(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        _pending_send_command: &mut Option<String>,
        pending_restart_active_tab: &mut bool,
        _pending_pin_shortcut: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let active_index = self.active_tab;
        let title_font = self.display_font(28.0);
        let active_tab_id = self.tabs[active_index].id;
        let terminal_widget_id = ui.make_persistent_id(("terminal_surface", active_tab_id));
        let terminal_has_focus = self.terminal_focus_tab_id == Some(active_tab_id)
            || ui.memory(|mem| mem.has_focus(terminal_widget_id));
        let mut should_handle_terminal_input = false;
        let mut pending_interrupt_echo = false;
        let mut pending_focus_terminal = false;
        let mut terminal_interacted = false;

        {
            let tab = &mut self.tabs[active_index];
            tab.unseen_output = false;

            if false {
                card_frame(palette, palette.panel, 14).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(&tab.title)
                            .font(title_font.clone())
                            .color(palette.text_primary),
                    );
                    badge(
                        ui,
                        palette,
                        &tab.status_text,
                        tab.status_color(palette).linear_multiply(0.18),
                        tab.status_color(palette),
                    );
                });

                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    stat_chip(ui, palette, "目标", tab.server.endpoint());
                    stat_chip(ui, palette, "会话", format!("#{}", tab.id));
                    stat_chip(ui, palette, "尝试", tab.connection_attempt.to_string());
                    stat_chip(ui, palette, "重连", tab.reconnect_count.to_string());
                    stat_chip(ui, palette, "在线时长", tab.uptime_text());
                    stat_chip(ui, palette, "终端", tab.terminal_identity());
                    if let Some(delay_secs) = tab.retry_delay_secs {
                        stat_chip(ui, palette, "退避", format!("{delay_secs}s"));
                    }
                });

                ui.label(
                    RichText::new(tab.server.connection_policy.summary())
                        .small()
                        .color(palette.text_secondary),
                );
                });
            }

            let available_height = ui.available_height();
            let terminal_height = (available_height - 56.0).max(280.0);
            let full_size = ui.available_size_before_wrap();
            let cols = ((full_size.x.max(520.0) / 8.4).floor() as u32).max(DEFAULT_TERMINAL_COLS);
            let rows =
                ((terminal_height.max(320.0) / 18.0).floor() as u32).max(DEFAULT_TERMINAL_ROWS);
            let desired = (cols, rows);
            if tab.last_terminal_size != Some(desired) {
                match tab.session.resize(
                    desired.0,
                    desired.1,
                    full_size.x as u32,
                    terminal_height as u32,
                ) {
                    Ok(()) => tab.last_terminal_size = Some(desired),
                    Err(error) => tab.push_system_message(&format!("调整终端尺寸失败: {error}")),
                }
            }

            let terminal_identity = tab.terminal_identity();
            let show_cursor = terminal_has_focus
                && matches!(tab.state, TabState::Connected)
                && ((ctx.input(|input| input.time) * 2.0).floor() as i64 % 2 == 0);
            if terminal_has_focus {
                ctx.request_repaint_after(Duration::from_millis(250));
            }

            egui::Frame::new()
                .fill(palette.terminal_bg)
                .stroke(Stroke::new(
                    if terminal_has_focus { 1.6 } else { 1.2 },
                    if terminal_has_focus {
                        palette.accent
                    } else {
                        palette.terminal_border
                    },
                ))
                .corner_radius(CornerRadius::same(20))
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.set_min_height(terminal_height);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").color(Color32::from_rgb(255, 120, 118)));
                        ui.label(RichText::new("●").color(Color32::from_rgb(255, 202, 88)));
                        ui.label(RichText::new("●").color(Color32::from_rgb(94, 214, 113)));
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(&terminal_identity)
                                .small()
                                .monospace()
                                .color(palette.text_secondary),
                        );
                    });
                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(6.0);
                    egui::ScrollArea::vertical()
                        .id_salt(("terminal_scroll", tab.id))
                        .stick_to_bottom(tab.auto_scroll)
                        .auto_shrink([false, false])
                        .max_height(terminal_height)
                        .show(ui, |ui| {
                            let mut layout_job = build_terminal_layout_job(
                                &tab.terminal_content,
                                palette,
                                &terminal_identity,
                                show_cursor,
                            );
                            layout_job.wrap.max_width = ui.available_width();
                            ui.set_width(ui.available_width());
                            let terminal_response = ui.add(
                                egui::Label::new(layout_job)
                                    .selectable(true)
                                    .sense(egui::Sense::click_and_drag()),
                            );
                            if terminal_response.clicked() || terminal_response.drag_started() {
                                ui.memory_mut(|mem| mem.request_focus(terminal_widget_id));
                                tab.auto_scroll = true;
                                pending_focus_terminal = true;
                                terminal_interacted = true;
                            }
                        });

                    let terminal_rect = ui.min_rect();
                    let response =
                        ui.interact(terminal_rect, terminal_widget_id, egui::Sense::click());
                    if response.clicked() {
                        ui.memory_mut(|mem| mem.request_focus(terminal_widget_id));
                        tab.auto_scroll = true;
                        pending_focus_terminal = true;
                        terminal_interacted = true;
                    }
                    should_handle_terminal_input = terminal_has_focus || response.has_focus();
                    if should_handle_terminal_input {
                        ui.memory_mut(|mem| mem.request_focus(terminal_widget_id));
                    }
                });

            card_frame(palette, palette.panel_soft, 12).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut tab.auto_scroll, "跟随输出");
                    if ui.button("清空终端").clicked() {
                        tab.terminal_content.clear();
                    }
                    if ui.button("重连").clicked() {
                        match tab.state {
                            TabState::Disconnected | TabState::Failed => {
                                *pending_restart_active_tab = true;
                            }
                            TabState::Connecting | TabState::Reconnecting | TabState::Connected => {
                                match tab.session.reconnect_now() {
                                    Ok(()) => tab.push_system_message("已发起重连请求。"),
                                    Err(error) => tab
                                        .push_system_message(&format!("发起重连请求失败: {error}")),
                                }
                            }
                        }
                    }
                    if ui.button("发送 Ctrl+C").clicked() {
                        match tab.session.interrupt() {
                            Ok(()) => pending_interrupt_echo = true,
                            Err(error) => {
                                tab.push_system_message(&format!("发送 Ctrl+C 失败: {error}"))
                            }
                        }
                    }
                    if ui.button("断开连接").clicked() {
                        match tab.session.disconnect() {
                            Ok(()) => tab.push_system_message("已发起断开请求。"),
                            Err(error) => {
                                tab.push_system_message(&format!("发起断开请求失败: {error}"))
                            }
                        }
                    }
                    ui.separator();
                    badge(
                        ui,
                        palette,
                        &terminal_identity,
                        palette.accent_soft,
                        palette.accent,
                    );
                    ui.label(
                        RichText::new(if terminal_has_focus {
                            "终端已聚焦，可直接输入"
                        } else {
                            "点击终端区域后可直接输入"
                        })
                        .small()
                        .color(palette.text_secondary),
                    );
                });
            });
        }

        if pending_interrupt_echo {
            self.echo_terminal_interrupt(active_index);
        }

        if pending_focus_terminal {
            self.terminal_focus_tab_id = Some(active_tab_id);
        } else if ctx.input(|input| input.pointer.any_click()) && !terminal_interacted {
            self.terminal_focus_tab_id = None;
        }

        if should_handle_terminal_input {
            self.handle_terminal_input(ctx, active_index);
        }
    }

    fn draw_terminal_shell_modern(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        _pending_send_command: &mut Option<String>,
        pending_restart_active_tab: &mut bool,
        _pending_pin_shortcut: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let active_index = self.active_tab;
        let active_tab_id = self.tabs[active_index].id;
        let terminal_widget_id = ui.make_persistent_id(("terminal_surface_modern", active_tab_id));
        let terminal_has_focus = self.terminal_focus_tab_id == Some(active_tab_id)
            || ui.memory(|mem| mem.has_focus(terminal_widget_id));
        let mut should_handle_terminal_input = false;
        let mut pending_interrupt_echo = false;
        let mut pending_focus_terminal = false;
        let mut terminal_interacted = false;

        {
            let tab = &mut self.tabs[active_index];
            tab.unseen_output = false;

            let available_height = ui.available_height();
            let terminal_height = available_height.max(340.0);
            let full_size = ui.available_size_before_wrap();
            let viewport_height = (terminal_height - 86.0).max(260.0);
            let cols = ((full_size.x.max(680.0) / 8.2).floor() as u32).max(DEFAULT_TERMINAL_COLS);
            let rows = ((viewport_height / 16.2).floor() as u32).max(DEFAULT_TERMINAL_ROWS);
            let desired = (cols, rows);
            if tab.last_terminal_size != Some(desired) {
                match tab.session.resize(desired.0, desired.1, full_size.x as u32, terminal_height as u32)
                {
                    Ok(()) => tab.last_terminal_size = Some(desired),
                    Err(error) => tab.push_system_message(&format!("调整终端尺寸失败: {error}")),
                }
            }

            let terminal_identity = tab.terminal_identity();
            let show_cursor = terminal_has_focus
                && matches!(tab.state, TabState::Connected)
                && ((ctx.input(|input| input.time) * 2.0).floor() as i64 % 2 == 0);
            if terminal_has_focus {
                ctx.request_repaint_after(Duration::from_millis(250));
            }

            egui::Frame::new()
                .fill(palette.terminal_bg.linear_multiply(1.04))
                .stroke(Stroke::new(
                    if terminal_has_focus { 1.3 } else { 1.0 },
                    if terminal_has_focus {
                        palette.success.linear_multiply(0.94)
                    } else {
                        palette.terminal_border
                    },
                ))
                .corner_radius(CornerRadius::same(22))
                .inner_margin(Margin::same(0))
                .shadow(Shadow {
                    offset: [0, 18],
                    blur: 42,
                    spread: 0,
                    color: palette.shadow,
                })
                .show(ui, |ui| {
                    ui.set_min_height(terminal_height);
                    ui.spacing_mut().item_spacing = vec2(0.0, 0.0);

                    egui::Frame::new()
                        .fill(Color32::from_rgba_premultiplied(255, 255, 255, 8))
                        .stroke(Stroke::new(0.0, Color32::TRANSPARENT))
                        .inner_margin(Margin::symmetric(14, 10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("●").color(Color32::from_rgb(255, 105, 97)));
                                ui.label(RichText::new("●").color(Color32::from_rgb(255, 189, 46)));
                                ui.label(RichText::new("●").color(Color32::from_rgb(39, 201, 63)));
                                ui.add_space(10.0);
                                ui.label(
                                    RichText::new(tab.server.endpoint())
                                        .small()
                                        .monospace()
                                        .color(palette.text_secondary),
                                );

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if terminal_toolbar_button(ui, palette, "断开").clicked() {
                                            match tab.session.disconnect() {
                                                Ok(()) => tab.push_system_message("已发起断开请求。"),
                                                Err(error) => tab.push_system_message(&format!(
                                                    "发起断开请求失败: {error}"
                                                )),
                                            }
                                        }
                                        if terminal_toolbar_button(ui, palette, "Ctrl+C").clicked() {
                                            match tab.session.interrupt() {
                                                Ok(()) => pending_interrupt_echo = true,
                                                Err(error) => tab.push_system_message(&format!(
                                                    "发送 Ctrl+C 失败: {error}"
                                                )),
                                            }
                                        }
                                        if terminal_toolbar_button(ui, palette, "重连").clicked() {
                                            match tab.state {
                                                TabState::Disconnected | TabState::Failed => {
                                                    *pending_restart_active_tab = true;
                                                }
                                                TabState::Connecting
                                                | TabState::Reconnecting
                                                | TabState::Connected => match tab
                                                    .session
                                                    .reconnect_now()
                                                {
                                                    Ok(()) => tab.push_system_message("已发起重连请求。"),
                                                    Err(error) => tab.push_system_message(&format!(
                                                        "发起重连请求失败: {error}"
                                                    )),
                                                },
                                            }
                                        }
                                        if terminal_toolbar_button(ui, palette, "清屏").clicked() {
                                            tab.terminal_content.clear();
                                        }
                                        badge(
                                            ui,
                                            palette,
                                            &tab.status_text,
                                            tab.status_color(palette).linear_multiply(0.18),
                                            tab.status_color(palette),
                                        );
                                    },
                                );
                            });
                        });

                    ui.add_space(4.0);

                    egui::Frame::new()
                        .fill(Color32::from_rgba_premultiplied(0, 0, 0, 0))
                        .inner_margin(Margin::symmetric(14, 10))
                        .show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .id_salt(("terminal_scroll_modern", tab.id))
                                .stick_to_bottom(tab.auto_scroll)
                                .auto_shrink([false, false])
                                .max_height(viewport_height)
                                .show(ui, |ui| {
                                    let mut layout_job = build_terminal_layout_job(
                                        &tab.terminal_content,
                                        palette,
                                        &terminal_identity,
                                        show_cursor,
                                    );
                                    layout_job.wrap.max_width = ui.available_width();
                                    ui.set_width(ui.available_width());
                                    let terminal_response = ui.add(
                                        egui::Label::new(layout_job)
                                            .selectable(true)
                                            .sense(egui::Sense::click_and_drag()),
                                    );
                                    if terminal_response.clicked() || terminal_response.drag_started() {
                                        ui.memory_mut(|mem| mem.request_focus(terminal_widget_id));
                                        tab.auto_scroll = true;
                                        pending_focus_terminal = true;
                                        terminal_interacted = true;
                                    }
                                });
                        });

                    ui.add_space(2.0);
                    egui::Frame::new()
                        .fill(Color32::from_rgba_premultiplied(255, 255, 255, 6))
                        .stroke(Stroke::new(0.0, Color32::TRANSPARENT))
                        .inner_margin(Margin::symmetric(14, 8))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut tab.auto_scroll, "自动跟随");
                                ui.separator();
                                ui.label(
                                    RichText::new(if terminal_has_focus {
                                        "终端已聚焦，可直接输入"
                                    } else {
                                        "点击终端区域后可直接输入"
                                    })
                                    .small()
                                    .color(palette.text_muted),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.label(
                                            RichText::new(format!("会话 #{}", tab.id))
                                                .small()
                                                .monospace()
                                                .color(palette.text_secondary),
                                        );
                                        ui.add_space(8.0);
                                        ui.label(
                                            RichText::new(&terminal_identity)
                                                .small()
                                                .monospace()
                                                .color(palette.success),
                                        );
                                    },
                                );
                            });
                        });

                    let terminal_rect = ui.min_rect();
                    let response =
                        ui.interact(terminal_rect, terminal_widget_id, egui::Sense::click());
                    if response.clicked() {
                        ui.memory_mut(|mem| mem.request_focus(terminal_widget_id));
                        tab.auto_scroll = true;
                        pending_focus_terminal = true;
                        terminal_interacted = true;
                    }
                    should_handle_terminal_input = terminal_has_focus || response.has_focus();
                    if should_handle_terminal_input {
                        ui.memory_mut(|mem| mem.request_focus(terminal_widget_id));
                    }
                });
        }

        if pending_interrupt_echo {
            self.echo_terminal_interrupt(active_index);
        }

        if pending_focus_terminal {
            self.terminal_focus_tab_id = Some(active_tab_id);
        } else if ctx.input(|input| input.pointer.any_click()) && !terminal_interacted {
            self.terminal_focus_tab_id = None;
        }

        if should_handle_terminal_input {
            self.handle_terminal_input(ctx, active_index);
        }
    }

    fn draw_connection_overview_card(&mut self, ui: &mut egui::Ui, palette: &ThemePalette) {
        let tab = &self.tabs[self.active_tab];

        card_frame(palette, palette.panel, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("连接概览")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                badge(
                    ui,
                    palette,
                    &tab.status_text,
                    tab.status_color(palette).linear_multiply(0.18),
                    tab.status_color(palette),
                );
            });

            ui.add_space(8.0);
            stat_chip(ui, palette, "当前会话", format!("#{}", tab.id));
            stat_chip(ui, palette, "目标", tab.server.endpoint());
            stat_chip(ui, palette, "在线时长", tab.uptime_text());
            stat_chip(ui, palette, "重连次数", tab.reconnect_count.to_string());
            ui.add_space(8.0);
            ui.label(
                RichText::new(tab.server.connection_policy.summary())
                    .small()
                    .color(palette.text_secondary),
            );
        });
    }

    fn draw_resource_workspace(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pending_connect: &mut Option<Server>,
        pending_run_command: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let _ = pending_connect;
        let active_endpoint = self.tabs[self.active_tab].server.endpoint();
        let title_font = self.display_font(24.0);
        card_frame(palette, palette.panel, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("资源管理")
                        .font(title_font.clone())
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new(format!("当前会话：{}", active_endpoint))
                        .small()
                        .color(palette.text_secondary),
                );
            });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                for resource_tab in [
                    ResourceTab::Overview,
                    ResourceTab::Files,
                    ResourceTab::Commands,
                    ResourceTab::Audit,
                    ResourceTab::Workspace,
                ] {
                    let selected = self.resource_tab == resource_tab;
                    if shell_pill(ui, palette, resource_tab.label(), selected, 10, 7).clicked() {
                        self.resource_tab = resource_tab;
                    }
                }
            });
        });

        ui.add_space(10.0);
        match self.resource_tab {
            ResourceTab::Overview => self.draw_connection_overview_card(ui, palette),
            ResourceTab::Files => self.draw_file_transfer_card(ui, palette),
            ResourceTab::Commands => self.draw_quick_actions_card(ui, pending_run_command, palette),
            ResourceTab::History | ResourceTab::Scripts => {
                self.resource_tab = ResourceTab::Commands;
                self.draw_quick_actions_card(ui, pending_run_command, palette);
            }
            ResourceTab::Audit => self.draw_audit_card(ui, palette),
            ResourceTab::Workspace => self.draw_workspace_card(ui, ctx, palette),
        }
    }

    fn draw_shell_top_bar(&mut self, ctx: &egui::Context) {
        let palette = self.palette();
        egui::TopBottomPanel::top("primary_app_tabs")
            .resizable(false)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(palette.panel.linear_multiply(0.82))
                    .stroke(Stroke::new(0.0, Color32::TRANSPARENT))
                    .inner_margin(Margin::symmetric(14, 10))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing = vec2(12.0, 0.0);
                        ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new("莓莓SSH终端")
                                    .font(self.display_font(24.0))
                                    .color(palette.text_primary),
                            );
                            ui.label(
                                RichText::new("面向 SSH 连接的现代桌面客户端")
                                    .small()
                                    .color(palette.text_muted),
                            );
                        });
                        ui.add_space(10.0);
                        egui::ScrollArea::horizontal()
                            .auto_shrink([false, true])
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    for page in [
                                        AppPage::Terminal,
                                        AppPage::Connections,
                                        AppPage::Settings,
                                        AppPage::Config,
                                    ] {
                                        let selected = self.app_page == page;
                                        if shell_pill(ui, &palette, page.label(), selected, 12, 7)
                                            .clicked()
                                        {
                                            self.app_page = page;
                                        }
                                    }
                                });
                            });
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                let connected_count = self
                                    .tabs
                                    .iter()
                                    .filter(|tab| tab.state == TabState::Connected)
                                    .count();
                                badge(
                                    ui,
                                    &palette,
                                    &format!("{connected_count} 在线"),
                                    palette.accent_soft,
                                    palette.text_primary,
                                );
                            },
                        );
                        ui.add_space(8.0);
                        let rect = ui.max_rect();
                        ui.painter().hline(
                            rect.x_range(),
                            rect.bottom() - 1.0,
                            Stroke::new(1.0, palette.stroke.linear_multiply(0.36)),
                        );
                    });
                });
            });
    }

    fn draw_shell_sidebar(&mut self, ctx: &egui::Context, pending_connect: &mut Option<Server>) {
        self.draw_server_panel_clean(ctx, pending_connect);
    }

    fn draw_tabs_bar(&mut self, ctx: &egui::Context, pending_close: &mut Option<usize>) {
        if self.tabs.is_empty() {
            return;
        }

        egui::TopBottomPanel::top("session_tabs_bar")
            .resizable(false)
            .show(ctx, |ui| {
                let palette = self.palette();
                card_frame(&palette, palette.panel_soft, 10).show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for index in 0..self.tabs.len() {
                            let selected = index == self.active_tab;
                            let title = self.tabs[index].title_for_tab();
                            if shell_pill(ui, &palette, &title, selected, 10, 6).clicked() {
                                self.active_tab = index;
                                self.tabs[index].unseen_output = false;
                            }
                            if ui.small_button("×").clicked() {
                                *pending_close = Some(index);
                            }
                        }
                    });
                });
            });
    }

    fn draw_global_tabs_bar(&mut self, ctx: &egui::Context, pending_close: &mut Option<usize>) {
        if self.tabs.is_empty() {
            return;
        }

        egui::TopBottomPanel::top("session_tabs_bar_v2")
            .resizable(false)
            .show(ctx, |ui| {
                let palette = self.palette();
                card_frame(&palette, palette.panel, 12).show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("莓莓SSH终端 · {} 个会话", self.tabs.len()))
                                .small()
                                .color(palette.text_secondary),
                        );
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if let Some(active) = self.tabs.get(self.active_tab) {
                                    badge(
                                        ui,
                                        &palette,
                                        &active.server.endpoint(),
                                        palette.panel_alt,
                                        palette.text_secondary,
                                    );
                                }
                            },
                        );
                    });

                    ui.add_space(8.0);
                    egui::ScrollArea::horizontal()
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                for index in 0..self.tabs.len() {
                                    let selected = index == self.active_tab;
                                    let title = self.tabs[index].title_for_tab();
                                    let status_color = self.tabs[index].status_color(&palette);
                                    let tab_fill = if selected {
                                        palette.panel_alt.linear_multiply(1.18)
                                    } else {
                                        palette.panel.linear_multiply(0.96)
                                    };
                                    let tab_stroke = if selected {
                                        palette.accent
                                    } else {
                                        palette.stroke.linear_multiply(0.9)
                                    };
                                    let title_color = if selected {
                                        palette.text_primary
                                    } else {
                                        palette.text_secondary
                                    };
                                    let close_color = if selected {
                                        palette.text_primary
                                    } else {
                                        palette.text_muted
                                    };
                                    egui::Frame::new()
                                        .fill(tab_fill)
                                        .stroke(Stroke::new(if selected { 1.4 } else { 1.0 }, tab_stroke))
                                        .corner_radius(CornerRadius::same(16))
                                        .inner_margin(Margin::symmetric(12, 9))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    RichText::new("●")
                                                        .small()
                                                        .color(status_color),
                                                );
                                                let response = ui.add(
                                                    egui::Button::new(
                                                        RichText::new(title)
                                                            .small()
                                                            .strong()
                                                            .color(title_color),
                                                    )
                                                    .frame(false),
                                                );
                                                if response.clicked() {
                                                    self.active_tab = index;
                                                    self.tabs[index].unseen_output = false;
                                                }
                                                if ui
                                                    .add(
                                                        egui::Button::new(
                                                            RichText::new("×")
                                                                .small()
                                                                .color(close_color),
                                                        )
                                                        .frame(false),
                                                    )
                                                    .clicked()
                                                {
                                                    *pending_close = Some(index);
                                                }
                                            });
                                        });
                                    ui.add_space(6.0);
                                }
                            });
                        });
                });
            });
    }

    fn draw_global_tabs_bar_modern(
        &mut self,
        ctx: &egui::Context,
        pending_close: &mut Option<usize>,
    ) {
        if self.tabs.is_empty() {
            return;
        }

        egui::TopBottomPanel::top("session_tabs_bar_modern")
            .resizable(false)
            .show(ctx, |ui| {
                let palette = self.palette();
                egui::Frame::new()
                    .fill(palette.panel.linear_multiply(0.62))
                    .stroke(Stroke::new(0.0, Color32::TRANSPARENT))
                    .inner_margin(Margin::symmetric(12, 8))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing = vec2(8.0, 0.0);
                        ui.horizontal(|ui| {
                            egui::ScrollArea::horizontal()
                                .auto_shrink([false, true])
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        for index in 0..self.tabs.len() {
                                            let selected = index == self.active_tab;
                                            let status_color = self.tabs[index].status_color(&palette);
                                            let title = self.tabs[index].title.clone();
                                            let tab_fill = if selected {
                                                palette.panel_alt.linear_multiply(1.14)
                                            } else {
                                                palette.panel.linear_multiply(0.92)
                                            };
                                            let tab_stroke = if selected {
                                                palette.success.linear_multiply(0.92)
                                            } else {
                                                palette.stroke.linear_multiply(0.4)
                                            };
                                            let title_color = if selected {
                                                palette.success
                                            } else {
                                                palette.text_secondary
                                            };

                                            egui::Frame::new()
                                                .fill(tab_fill)
                                                .stroke(Stroke::new(
                                                    if selected { 1.25 } else { 0.9 },
                                                    tab_stroke,
                                                ))
                                                .corner_radius(CornerRadius::same(14))
                                                .inner_margin(Margin::symmetric(12, 8))
                                                .show(ui, |ui| {
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            RichText::new("●")
                                                                .small()
                                                                .color(status_color),
                                                        );
                                                        let response = ui.add(
                                                            egui::Button::new(
                                                                RichText::new(title)
                                                                    .small()
                                                                    .strong()
                                                                    .color(title_color),
                                                            )
                                                            .frame(false),
                                                        );
                                                        if response.clicked() {
                                                            self.active_tab = index;
                                                            self.tabs[index].unseen_output = false;
                                                        }
                                                        if ui
                                                            .add(
                                                                egui::Button::new(
                                                                    RichText::new("×")
                                                                        .small()
                                                                        .color(if selected {
                                                                            palette.text_primary
                                                                        } else {
                                                                            palette.text_muted
                                                                        }),
                                                                )
                                                                .frame(false),
                                                            )
                                                            .clicked()
                                                        {
                                                            *pending_close = Some(index);
                                                        }
                                                    });
                                                });
                                        }
                                    });
                                });

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("+")
                                                    .strong()
                                                    .color(palette.text_secondary),
                                            )
                                            .frame(false),
                                        )
                                        .clicked()
                                    {
                                        self.app_page = AppPage::Connections;
                                    }
                                },
                            );
                        });
                    });
            });
    }

    fn draw_modal_backdrop(&self, ctx: &egui::Context) {
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("modal_backdrop"),
        ));
        painter.rect_filled(
            ctx.content_rect(),
            0.0,
            Color32::from_rgba_premultiplied(8, 12, 18, 92),
        );
    }

    fn draw_sync_dialog_modal(&mut self, ctx: &egui::Context) {
        if !self.show_sync_dialog {
            return;
        }

        let mut open = self.show_sync_dialog;
        egui::Window::new("同步中心")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_width(420.0);
                ui.label("登录后可同步主机列表、主题、快捷命令、脚本和历史。");
                ui.add_space(8.0);
                ui.label("账号");
                ui.add(
                    TextEdit::singleline(&mut self.sync_form.username).desired_width(f32::INFINITY),
                );
                ui.label("密码");
                ui.add(
                    TextEdit::singleline(&mut self.sync_form.password)
                        .password(true)
                        .desired_width(f32::INFINITY),
                );

                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("登录 / 注册").clicked() {
                        self.login_sync_account(ctx);
                    }
                    if ui.button("拉取").clicked() {
                        self.pull_from_sync_account(ctx);
                    }
                    if ui.button("推送").clicked() {
                        self.push_to_sync_account();
                    }
                    if ui.button("退出").clicked() {
                        self.logout_sync_account();
                    }
                });
            });
        self.show_sync_dialog = open;
    }

    fn draw_server_editor_dialog_modal(&mut self, ctx: &egui::Context) {
        if !self.show_server_editor_dialog {
            return;
        }

        let palette = self.palette();
        let mut open = self.show_server_editor_dialog;
        let title = if self.editing_server_key.is_some() {
            "编辑连接"
        } else {
            "新建连接"
        };

        egui::Window::new(title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .frame(glass_window_frame(&palette))
            .show(ctx, |ui| {
                ui.set_min_width(460.0);
                egui::Grid::new("server_form_grid_modal_minimal")
                    .num_columns(2)
                    .spacing([12.0, 10.0])
                    .show(ui, |ui| {
                        ui.label("名称");
                        ui.add(TextEdit::singleline(&mut self.server_form.name));
                        ui.end_row();

                        ui.label("主机");
                        ui.add(
                            TextEdit::singleline(&mut self.server_form.host)
                                .hint_text("例如：192.168.1.12 或 root@192.168.1.12"),
                        );
                        ui.end_row();

                        ui.label("端口");
                        ui.add(TextEdit::singleline(&mut self.server_form.port));
                        ui.end_row();

                        ui.label("用户");
                        ui.add(TextEdit::singleline(&mut self.server_form.user));
                        ui.end_row();

                        ui.label("分组");
                        ui.add(TextEdit::singleline(&mut self.server_form.group));
                        ui.end_row();
                    });

                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.selectable_value(
                        &mut self.server_form.auth_method,
                        AuthMethod::Password,
                        "密码",
                    );
                    ui.selectable_value(
                        &mut self.server_form.auth_method,
                        AuthMethod::PrivateKey,
                        "私钥",
                    );
                });

                match self.server_form.auth_method {
                    AuthMethod::Password => {
                        ui.label("密码");
                        ui.add(
                            TextEdit::singleline(&mut self.server_form.password)
                                .password(true)
                                .desired_width(f32::INFINITY),
                        );
                    }
                    AuthMethod::PrivateKey => {
                        ui.label("私钥路径");
                        ui.add(
                            TextEdit::singleline(&mut self.server_form.private_key_path)
                                .desired_width(f32::INFINITY),
                        );
                    }
                }

                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("保存").clicked() {
                        self.add_or_update_server_from_form();
                    }
                    if ui.button("取消").clicked() {
                        self.close_server_editor_dialog();
                    }
                });
            });
        self.show_server_editor_dialog = open;
    }

    fn draw_auth_prompt_modal(&mut self, ctx: &egui::Context) {
        let Some(mut dialog) = self.auth_prompt_dialog.take() else {
            return;
        };

        let palette = self.palette();
        let mut open = true;
        let mut submit = false;
        let mut cancel = false;

        egui::Window::new(dialog.title.clone())
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .frame(glass_window_frame(&palette))
            .show(ctx, |ui| {
                ui.set_width(460.0);

                if !dialog.instructions.trim().is_empty() {
                    ui.label(
                        RichText::new(dialog.instructions.clone())
                            .small()
                            .color(palette.text_secondary),
                    );
                    ui.add_space(10.0);
                }

                for (index, prompt) in dialog.prompts.iter().enumerate() {
                    ui.label(prompt.prompt.trim());
                    ui.add(
                        TextEdit::singleline(&mut dialog.responses[index])
                            .password(!prompt.echo)
                            .desired_width(f32::INFINITY),
                    );
                    ui.add_space(8.0);
                }

                ui.horizontal(|ui| {
                    if ui.button("提交").clicked() {
                        submit = true;
                    }
                    if ui.button("取消").clicked() {
                        cancel = true;
                    }
                });
            });

        if !open {
            cancel = true;
        }

        if submit {
            let tab_id = dialog.tab_id;
            let responses = dialog.responses.clone();
            if let Some(index) = self.tabs.iter().position(|tab| tab.id == tab_id) {
                match self.tabs[index].session.submit_auth_prompt(responses) {
                    Ok(()) => {
                        self.tabs[index]
                            .push_system_message("已提交认证信息。");
                    }
                    Err(error) => {
                        let message = format!("提交认证信息失败: {error}");
                        self.tabs[index].push_system_message(&message);
                        self.set_flash(message, true);
                        self.auth_prompt_dialog = Some(dialog);
                    }
                }
            }
        } else if cancel {
            if let Some(index) = self.tabs.iter().position(|tab| tab.id == dialog.tab_id) {
                let _ = self.tabs[index].session.disconnect();
                self.tabs[index].push_system_message("已从界面取消认证。");
            }
        } else {
            self.auth_prompt_dialog = Some(dialog);
        }
    }

    fn draw_delete_server_dialog(&mut self, ctx: &egui::Context) {
        let Some(server) = self.pending_delete_server.clone() else {
            return;
        };

        let palette = self.palette();
        let mut keep_open = true;
        egui::Window::new("删除连接")
            .open(&mut keep_open)
            .collapsible(false)
            .resizable(false)
            .frame(glass_window_frame(&palette))
            .show(ctx, |ui| {
                ui.label(format!("确认删除 `{}` 吗？", server.name));
                ui.label(server.endpoint());
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("删除").clicked() {
                        self.delete_server(&server.server_key());
                    }
                    if ui.button("取消").clicked() {
                        self.pending_delete_server = None;
                    }
                });
            });

        if !keep_open {
            self.pending_delete_server = None;
        }
    }

    fn draw_home_landing(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pending_connect: &mut Option<Server>,
        pending_run_command: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let _ = pending_run_command;
        if self.is_first_run() {
            self.draw_first_run_welcome(ui, ctx, palette);
            return;
        }

        match self.home_page {
            HomePage::Hosts => self.draw_hosts_gallery(ui, pending_connect, palette),
            HomePage::Sync => self.draw_sync_summary_card(ui, palette),
            HomePage::Scripts | HomePage::History => {
                self.home_page = HomePage::Hosts;
                self.draw_hosts_gallery(ui, pending_connect, palette);
            }
            HomePage::Audit => {
                self.draw_audit_card(ui, palette);
                ui.add_space(10.0);
                self.draw_workspace_card(ui, ctx, palette);
            }
        }
    }

    fn draw_first_run_welcome(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        palette: &ThemePalette,
    ) {
        ui.add_space(16.0);
        StripBuilder::new(ui)
            .size(Size::remainder().at_least(560.0))
            .size(Size::exact(18.0))
            .size(Size::exact(320.0))
            .horizontal(|mut strip| {
                strip.cell(|ui| {
                    card_frame(palette, palette.panel, 26).show(ui, |ui| {
                        badge(
                            ui,
                            palette,
                            "首次使用",
                            palette.accent_soft,
                            palette.text_primary,
                        );
                        ui.add_space(12.0);
                        ui.label(
                            RichText::new("先把第一台主机放进来")
                                .font(self.display_font(38.0))
                                .color(palette.text_primary),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(
                                "这一页现在会直接给出可操作的玻璃卡片，而不是空白状态。你可以先新建连接，再慢慢补同步、脚本、历史和工作区。",
                            )
                            .color(palette.text_secondary),
                        );
                        ui.add_space(16.0);

                        ui.horizontal_wrapped(|ui| {
                            if ui.button("新建第一台主机").clicked() {
                                self.open_new_server_dialog();
                            }
                            if ui.button("登录同步").clicked() {
                                self.open_sync_dialog();
                            }
                            if ui.button("导入工作区").clicked() {
                                self.import_workspace_snapshot(ctx);
                            }
                        });

                        ui.add_space(18.0);
                        ui.horizontal_wrapped(|ui| {
                            stat_chip(ui, palette, "已保存主机", "0");
                            stat_chip(ui, palette, "会话标签", "0");
                            stat_chip(ui, palette, "脚本中心", "就绪");
                            stat_chip(ui, palette, "文件传输", "就绪");
                        });

                        ui.add_space(18.0);
                        ui.columns(2, |columns| {
                            rich_info_card(
                                &mut columns[0],
                                palette,
                                "01",
                                "保存主机",
                                "先填主机、端口和用户名，密码或私钥后面再细调。",
                            );
                            rich_info_card(
                                &mut columns[1],
                                palette,
                                "02",
                                "打开终端",
                                "连接以后右侧就是会话区，左侧保留文件、命令和历史资源。",
                            );
                        });
                    });

                    ui.add_space(14.0);
                    ui.columns(3, |columns| {
                        rich_info_card(
                            &mut columns[0],
                            palette,
                            "终端",
                            "会话终端",
                            "保留 SSH 会话状态、重连控制和命令输入区。",
                        );
                        rich_info_card(
                            &mut columns[1],
                            palette,
                            "文件",
                            "文件传输",
                            "连接后就能浏览远端目录，上传、下载和新建目录。",
                        );
                        rich_info_card(
                            &mut columns[2],
                            palette,
                            "脚本",
                            "脚本与历史",
                            "常用命令、收藏脚本和访问记录都会沉淀下来。",
                        );
                    });
                });

                strip.cell(|ui| {
                    ui.add_space(6.0);
                });

                strip.cell(|ui| {
                    card_frame(palette, palette.panel_soft, 20).show(ui, |ui| {
                        ui.label(
                            RichText::new("快速开始")
                                .font(self.display_font(24.0))
                                .color(palette.text_primary),
                        );
                        ui.add_space(10.0);
                        rich_step_row(
                            ui,
                            palette,
                            "1",
                            "新建连接",
                            "把最常用的一台先加进来。",
                        );
                        rich_step_row(
                            ui,
                            palette,
                            "2",
                            "连接测试",
                            "确认密码、私钥和网络都可用。",
                        );
                        rich_step_row(
                            ui,
                            palette,
                            "3",
                            "沉淀资源",
                            "把常用命令和脚本留在这里。",
                        );
                    });

                    ui.add_space(14.0);
                    card_frame(palette, palette.panel_alt, 18).show(ui, |ui| {
                        ui.label(
                            RichText::new("推荐首个模板")
                                .font(self.display_font(22.0))
                                .color(palette.text_primary),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("主机: 192.168.1.10\n端口: 22\n用户: ubuntu")
                                .monospace()
                                .color(palette.text_secondary),
                        );
                        ui.add_space(10.0);
                        ui.horizontal_wrapped(|ui| {
                            badge(
                                ui,
                                palette,
                                "密码 / 密钥",
                                palette.panel_soft,
                                palette.text_secondary,
                            );
                            badge(
                                ui,
                                palette,
                                "自动重连",
                                palette.panel_soft,
                                palette.text_secondary,
                            );
                        });
                    });

                    ui.add_space(14.0);
                    card_frame(palette, palette.panel_soft, 18).show(ui, |ui| {
                        ui.label(
                            RichText::new("背景已恢复")
                                .font(self.display_font(22.0))
                                .color(palette.text_primary),
                        );
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(
                                "这版把背景图和玻璃卡片分开处理了。背景会露出来，内容则落在一块一块的半透明面板上。",
                            )
                            .color(palette.text_secondary),
                        );
                    });
                });
            });
    }

    #[allow(unreachable_code)]
    fn draw_hosts_gallery(
        &mut self,
        ui: &mut egui::Ui,
        pending_connect: &mut Option<Server>,
        palette: &ThemePalette,
    ) {
        self.draw_hosts_gallery_modern(ui, pending_connect, palette);
        return;

        let mut grouped: BTreeMap<String, Vec<Server>> = BTreeMap::new();
        for server in self
            .servers
            .iter()
            .filter(|server| server.matches_query(&self.search_query))
            .cloned()
        {
            grouped
                .entry(server.group_name().to_string())
                .or_default()
                .push(server);
        }

        let mut pending_edit: Option<Server> = None;
        let mut pending_delete: Option<Server> = None;
        let mut pending_focus_server_key: Option<String> = None;

        card_frame(palette, palette.panel, 18).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("主机浏览")
                        .font(self.display_font(32.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new("像参考图那样做成更轻一点的浏览页，分组和主机都直接卡片化。")
                        .small()
                        .color(palette.text_secondary),
                );
            });

            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.search_query)
                        .hint_text("搜索主机、用户、分组")
                        .desired_width(320.0),
                );
                if ui.button("新建连接").clicked() {
                    self.open_new_server_dialog();
                }
                if ui.button("同步中心").clicked() {
                    self.open_sync_dialog();
                }
                if ui.button("脚本中心").clicked() {
                    self.home_page = HomePage::Scripts;
                }
            });

            ui.add_space(14.0);
            ui.label(RichText::new("分组").strong().color(palette.text_primary));
            ui.add_space(8.0);

            if grouped.is_empty() {
                card_frame(palette, palette.panel_soft, 16).show(ui, |ui| {
                    ui.label(
                        RichText::new("当前还没有匹配的主机。先新建一台，或者换一个搜索词。")
                            .color(palette.text_secondary),
                    );
                });
                return;
            }

            ui.horizontal_wrapped(|ui| {
                for (index, (group, servers)) in grouped.iter().enumerate() {
                    let open_count = servers
                        .iter()
                        .filter(|server| {
                            self.tabs
                                .iter()
                                .any(|tab| tab.server.server_key() == server.server_key())
                        })
                        .count();
                    let tint = host_card_tint(palette, index);

                    egui::Frame::new()
                        .fill(palette.panel_soft.linear_multiply(1.06))
                        .stroke(Stroke::new(1.0, tint.linear_multiply(0.42)))
                        .corner_radius(CornerRadius::same(24))
                        .inner_margin(Margin::same(14))
                        .shadow(Shadow {
                            offset: [0, 16],
                            blur: 34,
                            spread: 0,
                            color: palette.shadow,
                        })
                        .show(ui, |ui| {
                            ui.set_width(240.0);
                            ui.horizontal_wrapped(|ui| {
                                egui::Frame::new()
                                    .fill(tint.linear_multiply(0.28))
                                    .corner_radius(CornerRadius::same(14))
                                    .inner_margin(Margin::same(10))
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(
                                                group.chars().next().unwrap_or('组').to_string(),
                                            )
                                            .strong()
                                            .color(tint),
                                        );
                                    });
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(group).strong().color(palette.text_primary),
                                    );
                                    ui.label(
                                        RichText::new(format!("{} 台主机", servers.len()))
                                            .small()
                                            .color(palette.text_secondary),
                                    );
                                    if open_count > 0 {
                                        ui.label(
                                            RichText::new(format!("{open_count} 台已打开"))
                                                .small()
                                                .color(palette.text_muted),
                                        );
                                    }
                                });
                            });
                        });

                    if index % 3 != 2 {
                        ui.add_space(6.0);
                    }
                }
            });

            ui.add_space(16.0);
            ui.label(RichText::new("主机").strong().color(palette.text_primary));
            ui.add_space(8.0);

            // Use fixed-width host cards so the page keeps the same tidy rhythm on most window sizes.
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let mut color_index = 0usize;
                        for servers in grouped.values() {
                            for server in servers {
                                let open_tabs = self
                                    .tabs
                                    .iter()
                                    .filter(|tab| tab.server.server_key() == server.server_key())
                                    .count();
                                let already_open = open_tabs > 0;
                                let tint = host_card_tint(palette, color_index);
                                color_index += 1;

                                ui.allocate_ui_with_layout(
                                    vec2(286.0, 136.0),
                                    egui::Layout::top_down(egui::Align::Min),
                                    |ui| {
                                        egui::Frame::new()
                                            .fill(palette.panel_soft.linear_multiply(1.08))
                                            .stroke(Stroke::new(1.0, tint.linear_multiply(0.36)))
                                            .corner_radius(CornerRadius::same(24))
                                            .inner_margin(Margin::same(14))
                                            .shadow(Shadow {
                                                offset: [0, 16],
                                                blur: 36,
                                                spread: 0,
                                                color: palette.shadow,
                                            })
                                            .show(ui, |ui| {
                                                ui.set_min_width(258.0);
                                                ui.horizontal_wrapped(|ui| {
                                                    egui::Frame::new()
                                                        .fill(tint.linear_multiply(0.26))
                                                        .corner_radius(CornerRadius::same(14))
                                                        .inner_margin(Margin::same(10))
                                                        .show(ui, |ui| {
                                                            ui.label(
                                                                RichText::new(host_card_symbol(
                                                                    server,
                                                                ))
                                                                .strong()
                                                                .color(tint),
                                                            );
                                                        });
                                                    ui.vertical(|ui| {
                                                        ui.label(
                                                            RichText::new(&server.name)
                                                                .strong()
                                                                .color(palette.text_primary),
                                                        );
                                                        ui.label(
                                                            RichText::new(&server.host)
                                                                .small()
                                                                .color(palette.text_secondary),
                                                        );
                                                    });
                                                    ui.with_layout(
                                                        egui::Layout::right_to_left(
                                                            egui::Align::Center,
                                                        ),
                                                        |ui| {
                                                            if already_open {
                                                                badge(
                                                                    ui,
                                                                    palette,
                                                                    "已打开",
                                                                    palette.accent_soft,
                                                                    palette.text_primary,
                                                                );
                                                                ui.label(
                                                                    RichText::new("再次点击会新开一个标签")
                                                                        .small()
                                                                        .color(palette.text_muted),
                                                                );
                                                                if ui.small_button("切到最新").clicked() {
                                                                    pending_focus_server_key =
                                                                        Some(server.server_key());
                                                                }
                                                            }
                                                        },
                                                    );
                                                });

                                                ui.add_space(8.0);
                                                ui.label(
                                                    RichText::new(server.endpoint())
                                                        .small()
                                                        .color(palette.text_secondary),
                                                );
                                                ui.horizontal_wrapped(|ui| {
                                                    badge(
                                                        ui,
                                                        palette,
                                                        server.group_name(),
                                                        palette.panel_alt,
                                                        palette.text_secondary,
                                                    );
                                                    badge(
                                                        ui,
                                                        palette,
                                                        server.auth_method.label(),
                                                        palette.panel_alt,
                                                        palette.text_secondary,
                                                    );
                                                });

                                                ui.add_space(8.0);
                                                ui.horizontal_wrapped(|ui| {
                                                    if ui
                                                        .button(if already_open {
                                                            "回到会话"
                                                        } else {
                                                            "连接"
                                                        })
                                                        .clicked()
                                                    {
                                                        *pending_connect = Some(server.clone());
                                                    }
                                                    if ui.small_button("编辑").clicked() {
                                                        pending_edit = Some(server.clone());
                                                    }
                                                    if ui.small_button("删除").clicked() {
                                                        pending_delete = Some(server.clone());
                                                    }
                                                });
                                            });
                                    },
                                );
                                ui.add_space(8.0);
                            }
                        }
                    });
                });
        });

        if let Some(server) = pending_edit {
            self.start_editing_server(&server);
        }
        if let Some(server) = pending_delete {
            self.request_server_delete(server);
        }
        if let Some(server_key) = pending_focus_server_key {
            let _ = self.focus_existing_session_tab(&server_key);
        }
    }

    fn draw_hosts_gallery_modern(
        &mut self,
        ui: &mut egui::Ui,
        pending_connect: &mut Option<Server>,
        palette: &ThemePalette,
    ) {
        let servers: Vec<Server> = self
            .servers
            .iter()
            .filter(|server| server.matches_query(&self.search_query))
            .cloned()
            .collect();
        let mut grouped: BTreeMap<String, Vec<Server>> = BTreeMap::new();
        for server in &servers {
            grouped
                .entry(server.group_name().to_string())
                .or_default()
                .push(server.clone());
        }
        let active_count = servers
            .iter()
            .filter(|server| {
                self.tabs
                    .iter()
                    .any(|tab| tab.server.server_key() == server.server_key())
            })
            .count();
        let mut pending_edit: Option<Server> = None;
        let mut pending_delete: Option<Server> = None;
        let mut pending_focus_server_key: Option<String> = None;

        card_frame(palette, palette.panel, 18).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("主机列表")
                            .font(self.display_font(30.0))
                            .color(palette.text_primary),
                    );
                    ui.label(
                        RichText::new("更紧凑的深色运维面板风格，点击卡片直接打开新会话。")
                            .small()
                            .color(palette.text_secondary),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("新建连接").clicked() {
                        self.open_new_server_dialog();
                    }
                });
            });

            ui.add_space(14.0);
            ui.add(
                TextEdit::singleline(&mut self.search_query)
                    .hint_text("搜索主机、用户、分组")
                    .desired_width(360.0),
            );
            ui.add_space(10.0);
            ui.horizontal_wrapped(|ui| {
                stat_chip(ui, palette, "主机数量", servers.len().to_string());
                stat_chip(ui, palette, "已打开", active_count.to_string());
                stat_chip(ui, palette, "分组", grouped.len().to_string());
            });

            ui.add_space(16.0);
            if grouped.is_empty() {
                card_frame(palette, palette.panel_soft, 16).show(ui, |ui| {
                    ui.label(
                        RichText::new("当前没有匹配的主机。可以先新建连接，或者换一个搜索关键词。")
                            .color(palette.text_secondary),
                    );
                });
                return;
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (index, server) in servers.iter().enumerate() {
                            let tint = host_card_tint(palette, index);
                            let already_open = self
                                .tabs
                                .iter()
                                .any(|tab| tab.server.server_key() == server.server_key());

                            ui.allocate_ui_with_layout(
                                vec2(314.0, 138.0),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                                    let card = egui::Frame::new()
                                        .fill(palette.panel_alt.linear_multiply(1.02))
                                        .stroke(Stroke::new(
                                            if already_open { 1.2 } else { 1.0 },
                                            if already_open {
                                                tint.linear_multiply(0.58)
                                            } else {
                                                palette.stroke.linear_multiply(0.58)
                                            },
                                        ))
                                        .corner_radius(CornerRadius::same(24))
                                        .inner_margin(Margin::symmetric(14, 13))
                                        .shadow(Shadow {
                                            offset: [0, 16],
                                            blur: 24,
                                            spread: 0,
                                            color: palette.shadow,
                                        })
                                        .show(ui, |ui| {
                                            ui.set_min_width(286.0);
                                            ui.horizontal(|ui| {
                                                egui::Frame::new()
                                                    .fill(tint.linear_multiply(0.24))
                                                    .stroke(Stroke::new(1.0, tint.linear_multiply(0.52)))
                                                    .corner_radius(CornerRadius::same(14))
                                                    .inner_margin(Margin::symmetric(10, 9))
                                                    .show(ui, |ui| {
                                                        ui.label(
                                                            RichText::new(host_card_pill_label(server))
                                                                .small()
                                                                .strong()
                                                                .color(tint),
                                                        );
                                                    });

                                                ui.add_space(8.0);
                                                ui.vertical(|ui| {
                                                    ui.label(
                                                        RichText::new(&server.name)
                                                            .strong()
                                                            .color(palette.text_primary),
                                                    );
                                                    ui.label(
                                                        RichText::new(format!(
                                                            "{}  ·  {}",
                                                            host_card_meta(server),
                                                            server.group_name()
                                                        ))
                                                        .small()
                                                        .color(palette.text_muted),
                                                    );
                                                });

                                                ui.with_layout(
                                                    egui::Layout::right_to_left(egui::Align::Center),
                                                    |ui| {
                                                        if already_open {
                                                            badge(
                                                                ui,
                                                                palette,
                                                                "已打开",
                                                                tint.linear_multiply(0.18),
                                                                tint,
                                                            );
                                                        }
                                                    },
                                                );
                                            });

                                            ui.add_space(10.0);
                                            ui.label(
                                                RichText::new(server.endpoint())
                                                    .small()
                                                    .color(palette.text_secondary),
                                            );
                                            ui.add_space(8.0);
                                            ui.horizontal_wrapped(|ui| {
                                                badge(
                                                    ui,
                                                    palette,
                                                    server.group_name(),
                                                    palette.panel_soft,
                                                    palette.text_secondary,
                                                );
                                                badge(
                                                    ui,
                                                    palette,
                                                    server.auth_method.label(),
                                                    palette.panel_soft,
                                                    palette.text_secondary,
                                                );
                                                badge(
                                                    ui,
                                                    palette,
                                                    if server.connection_policy.auto_reconnect {
                                                        "自动重连"
                                                    } else {
                                                        "单次连接"
                                                    },
                                                    palette.panel_soft,
                                                    palette.text_muted,
                                                );
                                            });
                                            ui.add_space(10.0);
                                            ui.horizontal_wrapped(|ui| {
                                                if ui
                                                    .button(if already_open { "新建会话" } else { "连接" })
                                                    .clicked()
                                                {
                                                    *pending_connect = Some(server.clone());
                                                }
                                                if already_open && ui.small_button("定位标签").clicked() {
                                                    pending_focus_server_key =
                                                        Some(server.server_key());
                                                }
                                                if ui.small_button("编辑").clicked() {
                                                    pending_edit = Some(server.clone());
                                                }
                                                if ui.small_button("删除").clicked() {
                                                    pending_delete = Some(server.clone());
                                                }
                                            });
                                        });

                                    let response = card.response.interact(egui::Sense::click());
                                    if response.clicked() {
                                        *pending_connect = Some(server.clone());
                                    }
                                },
                            );
                            ui.add_space(10.0);
                        }
                    });
                });
        });

        if let Some(server) = pending_edit {
            self.start_editing_server(&server);
        }
        if let Some(server) = pending_delete {
            self.request_server_delete(server);
        }
        if let Some(server_key) = pending_focus_server_key {
            let _ = self.focus_existing_session_tab(&server_key);
        }
    }

    fn draw_sync_summary_card(&mut self, ui: &mut egui::Ui, palette: &ThemePalette) {
        card_frame(palette, palette.panel, 18).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("同步中心")
                        .font(self.display_font(28.0))
                        .color(palette.text_primary),
                );
                let status = self
                    .logged_in_user
                    .as_deref()
                    .map(|user| format!("当前账号：{user}"))
                    .unwrap_or_else(|| "当前未登录".to_string());
                badge(
                    ui,
                    palette,
                    &status,
                    palette.panel_alt,
                    palette.text_secondary,
                );
            });

            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "这里保留一个更简洁的同步概览，真正的账号输入和推拉快照都放到弹窗里。",
                )
                .color(palette.text_secondary),
            );

            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                stat_chip(
                    ui,
                    palette,
                    "自动同步",
                    if self.settings.auto_sync_on_login {
                        "已开启"
                    } else {
                        "未开启"
                    },
                );
                stat_chip(ui, palette, "最近主题", self.settings.theme_preset.label());
                stat_chip(ui, palette, "主机数量", self.servers.len().to_string());
            });

            ui.add_space(12.0);
            if ui.button("打开同步弹窗").clicked() {
                self.open_sync_dialog();
            }
        });
    }

    fn draw_workspace(
        &mut self,
        ctx: &egui::Context,
        pending_connect: &mut Option<Server>,
        pending_run_command: &mut Option<String>,
        pending_send_command: &mut Option<String>,
        pending_restart_active_tab: &mut bool,
        pending_pin_shortcut: &mut Option<String>,
    ) {
        let palette = self.palette();
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.spacing_mut().item_spacing = vec2(10.0, 10.0);

            match self.app_page {
                AppPage::Terminal => {
                    if self.tabs.is_empty() {
                        card_frame(&palette, palette.panel, 20).show(ui, |ui| {
                            ui.label(
                                RichText::new("先建立一个 SSH 连接，再开始终端会话")
                                    .font(self.display_font(28.0))
                                    .color(palette.text_primary),
                            );
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new(
                                    "莓莓SSH终端的定位是 PuTTY、Termius、SecureCRT 和 macOS Terminal.app 的替代方案。先到连接页面新建或打开主机，再开始你的 SSH 会话。",
                                )
                                .color(palette.text_secondary),
                            );
                            ui.add_space(12.0);
                            if ui.button("前往 SSH 连接").clicked() {
                                self.app_page = AppPage::Connections;
                            }
                        });
                    } else {
                        self.draw_terminal_workbench(
                            ui,
                            ctx,
                            pending_connect,
                            pending_run_command,
                            pending_send_command,
                            pending_restart_active_tab,
                            pending_pin_shortcut,
                            &palette,
                        );
                    }
                }
                AppPage::Connections => {
                    self.home_page = HomePage::Hosts;
                    self.draw_home_landing(ui, ctx, pending_connect, pending_run_command, &palette);
                }
                AppPage::Settings => {
                    self.draw_settings_page(ui, ctx, &palette);
                }
                AppPage::Config => {
                    self.draw_config_page(ui, ctx, &palette);
                }
            }
        });
    }

    fn draw_terminal_workbench(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pending_connect: &mut Option<Server>,
        pending_run_command: &mut Option<String>,
        pending_send_command: &mut Option<String>,
        pending_restart_active_tab: &mut bool,
        pending_pin_shortcut: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let current = self.terminal_workbench_tab;
        card_frame(palette, palette.panel, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(current.label())
                            .font(self.display_font(26.0))
                            .color(palette.text_primary),
                    );
                    ui.label(
                        RichText::new(current.subtitle())
                            .small()
                            .color(palette.text_secondary),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    for tab in [
                        TerminalWorkbenchTab::Theme,
                        TerminalWorkbenchTab::Sftp,
                        TerminalWorkbenchTab::Vault,
                        TerminalWorkbenchTab::SplitTerminal,
                    ] {
                        if shell_pill(
                            ui,
                            palette,
                            tab.label(),
                            self.terminal_workbench_tab == tab,
                            12,
                            8,
                        )
                        .clicked()
                        {
                            self.terminal_workbench_tab = tab;
                        }
                    }
                });
            });
        });

        ui.add_space(10.0);
        match self.terminal_workbench_tab {
            TerminalWorkbenchTab::SplitTerminal => self.draw_terminal_split_workspace(
                ui,
                ctx,
                pending_run_command,
                pending_send_command,
                pending_restart_active_tab,
                pending_pin_shortcut,
                palette,
            ),
            TerminalWorkbenchTab::Vault => {
                self.draw_terminal_vault_view(ui, ctx, pending_connect, pending_run_command, palette);
            }
            TerminalWorkbenchTab::Sftp => {
                self.draw_terminal_sftp_view(ui, ctx, palette);
            }
            TerminalWorkbenchTab::Theme => {
                self.draw_terminal_theme_view(ui, ctx, palette);
            }
        }
    }

    fn draw_terminal_split_workspace(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pending_run_command: &mut Option<String>,
        pending_send_command: &mut Option<String>,
        pending_restart_active_tab: &mut bool,
        pending_pin_shortcut: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let width = ui.available_width();
        if width < 1160.0 {
            self.draw_terminal_shell_modern(
                ui,
                ctx,
                pending_send_command,
                pending_restart_active_tab,
                pending_pin_shortcut,
                palette,
            );
            ui.add_space(10.0);
            self.draw_quick_actions_card(ui, pending_run_command, palette);
            return;
        }

        StripBuilder::new(ui)
            .size(Size::remainder().at_least(720.0))
            .size(Size::exact(340.0))
            .horizontal(|mut strip| {
                strip.cell(|ui| {
                    self.draw_terminal_shell_modern(
                        ui,
                        ctx,
                        pending_send_command,
                        pending_restart_active_tab,
                        pending_pin_shortcut,
                        palette,
                    );
                });
                strip.cell(|ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            self.draw_connection_overview_card(ui, palette);
                            ui.add_space(10.0);
                            self.draw_quick_actions_card(ui, pending_run_command, palette);
                            ui.add_space(10.0);
                            self.draw_audit_card(ui, palette);
                        });
                });
            });
    }

    fn draw_terminal_vault_view(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        pending_connect: &mut Option<Server>,
        pending_run_command: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let width = ui.available_width();
        if width < 1120.0 {
            self.draw_quick_actions_card(ui, pending_run_command, palette);
            ui.add_space(10.0);
            self.draw_history_card(ui, pending_connect, palette);
            ui.add_space(10.0);
            self.draw_audit_card(ui, palette);
            ui.add_space(10.0);
            self.draw_workspace_card(ui, ctx, palette);
            return;
        }

        ui.columns(2, |columns| {
            columns[0].spacing_mut().item_spacing = vec2(10.0, 10.0);
            columns[1].spacing_mut().item_spacing = vec2(10.0, 10.0);

            self.draw_quick_actions_card(&mut columns[0], pending_run_command, palette);
            self.draw_history_card(&mut columns[0], pending_connect, palette);

            self.draw_audit_card(&mut columns[1], palette);
            columns[1].add_space(10.0);
            self.draw_workspace_card(&mut columns[1], ctx, palette);
        });
    }

    fn draw_terminal_sftp_view(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        palette: &ThemePalette,
    ) {
        card_frame(palette, palette.panel_soft, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("SFTP 文件传输")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new("像专业 SSH 客户端一样处理远程目录、上传下载、建目录与清理。")
                        .small()
                        .color(palette.text_secondary),
                );
            });
        });

        ui.add_space(10.0);
        self.draw_file_transfer_card(ui, palette);
        ui.add_space(10.0);
        self.draw_workspace_card(ui, ctx, palette);
    }

    fn draw_terminal_theme_view(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        palette: &ThemePalette,
    ) {
        card_frame(palette, palette.panel_soft, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("SSH 客户端主题")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new("统一控制终端、导航、卡片与背景，让整套 SSH 体验风格一致。")
                        .small()
                        .color(palette.text_secondary),
                );
            });
        });

        ui.add_space(10.0);
        self.draw_settings_page(ui, ctx, palette);
    }

    fn draw_settings_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, palette: &ThemePalette) {
        card_frame(palette, palette.panel, 18).show(ui, |ui| {
            ui.label(
                RichText::new("外观设置")
                    .font(self.display_font(28.0))
                    .color(palette.text_primary),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("主题、终端外观以及全局视觉偏好都放在这里。")
                    .color(palette.text_secondary),
            );
        });

        ui.add_space(10.0);
        card_frame(palette, palette.panel_soft, 18).show(ui, |ui| {
            ui.label(RichText::new("主题预设").strong().color(palette.text_primary));
            ui.add_space(8.0);
            let mut selected_theme = self.settings.theme_preset;
            ui.horizontal_wrapped(|ui| {
                for preset in [
                    ThemePreset::PeachBlossom,
                    ThemePreset::Celadon,
                    ThemePreset::Vermilion,
                ] {
                    if shell_pill(ui, palette, preset.label(), selected_theme == preset, 12, 8)
                        .clicked()
                    {
                        selected_theme = preset;
                    }
                }
            });
            if selected_theme != self.settings.theme_preset {
                self.update_theme(ctx, selected_theme);
            }
            ui.add_space(8.0);
            ui.label(
                RichText::new(self.settings.theme_preset.subtitle())
                    .small()
                    .color(palette.text_muted),
            );
        });
    }

    fn draw_config_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, palette: &ThemePalette) {
        card_frame(palette, palette.panel, 18).show(ui, |ui| {
            ui.label(
                RichText::new("系统配置")
                    .font(self.display_font(28.0))
                    .color(palette.text_primary),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("同步、工作区和应用级配置已经拆分到这里。")
                    .color(palette.text_secondary),
            );
        });

        ui.add_space(10.0);
        self.draw_sync_summary_card(ui, palette);
        ui.add_space(10.0);
        self.draw_workspace_card(ui, ctx, palette);
    }

    fn draw_history_card(
        &mut self,
        ui: &mut egui::Ui,
        pending_connect: &mut Option<Server>,
        palette: &ThemePalette,
    ) {
        let grouped_history = self.grouped_connection_history();
        let mut pending_prefill: Option<ConnectionHistory> = None;

        card_frame(palette, palette.panel, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("分组历史")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new("最近的 SSH 访问会按照服务器分组收纳。")
                        .small()
                        .color(palette.text_secondary),
                );
            });

            if grouped_history.is_empty() {
                ui.label(
                    RichText::new("先打开一个会话，分组历史就会慢慢积累起来。")
                        .color(palette.text_muted),
                );
                return;
            }

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(360.0)
                .show(ui, |ui| {
                    for (index, (group, entries)) in grouped_history.into_iter().enumerate() {
                        egui::CollapsingHeader::new(format!("{group} ({})", entries.len()))
                            .default_open(index < 3)
                            .show(ui, |ui| {
                                for entry in entries.into_iter().take(HISTORY_GROUP_LIMIT) {
                                    egui::Frame::new()
                                        .fill(palette.panel_alt)
                                        .stroke(Stroke::new(1.0, palette.stroke))
                                        .corner_radius(CornerRadius::same(16))
                                        .inner_margin(Margin::same(10))
                                        .show(ui, |ui| {
                                            ui.horizontal_wrapped(|ui| {
                                                ui.label(
                                                    RichText::new(&entry.server_name)
                                                        .strong()
                                                        .color(palette.text_primary),
                                                );
                                                badge(
                                                    ui,
                                                    palette,
                                                    &friendly_time(entry.timestamp),
                                                    palette.panel_soft,
                                                    palette.text_secondary,
                                                );
                                            });
                                            ui.label(
                                                RichText::new(entry.endpoint())
                                                    .small()
                                                    .color(palette.text_secondary),
                                            );

                                            let saved_server = self.server_for_history(&entry);
                                            ui.horizontal_wrapped(|ui| {
                                                if let Some(server) = saved_server {
                                                    if ui.button("连接").clicked() {
                                                        *pending_connect = Some(server);
                                                    }
                                                } else {
                                                    ui.label(
                                                        RichText::new("未找到已保存配置")
                                                            .small()
                                                            .color(palette.warning),
                                                    );
                                                }

                                                if ui.button("回填表单").clicked() {
                                                    pending_prefill = Some(entry.clone());
                                                }
                                            });
                                        });
                                    ui.add_space(6.0);
                                }
                            });
                    }
                });
        });

        if let Some(entry) = pending_prefill {
            self.prefill_from_history(&entry);
        }
    }

    fn draw_quick_actions_card(
        &mut self,
        ui: &mut egui::Ui,
        pending_run_command: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let active_server = self.tabs.get(self.active_tab).map(|tab| tab.server.clone());
        let mut pending_remove_shortcut: Option<usize> = None;

        card_frame(palette, palette.panel_soft, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("快捷操作")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                if let Some(server) = &active_server {
                    ui.label(
                        RichText::new(server.connection_policy.summary())
                            .small()
                            .color(palette.text_secondary),
                    );
                } else {
                    ui.label(
                        RichText::new("打开任意标签页后，就能一键运行排障命令。")
                            .small()
                            .color(palette.text_secondary),
                    );
                }
            });

            if let Some(server) = &active_server {
                ui.label(
                    RichText::new(format!("当前目标：{}", server.endpoint()))
                        .small()
                        .color(palette.text_muted),
                );
                ui.add_space(6.0);

                for (label, command, description) in BUILTIN_SHORTCUTS {
                    if ui.button(label).clicked() {
                        *pending_run_command = Some(command.to_string());
                    }
                    ui.label(RichText::new(description).small().color(palette.text_muted));
                    ui.add_space(4.0);
                }

                if !self.shortcuts.is_empty() {
                    ui.separator();
                    ui.label(
                        RichText::new("收藏命令")
                            .strong()
                            .color(palette.text_primary),
                    );
                    for (index, shortcut) in self.shortcuts.iter().enumerate() {
                        egui::Frame::new()
                            .fill(palette.panel_alt)
                            .stroke(Stroke::new(1.0, palette.stroke))
                            .corner_radius(CornerRadius::same(14))
                            .inner_margin(Margin::same(10))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    if ui.button(&shortcut.name).clicked() {
                                        *pending_run_command = Some(shortcut.command.clone());
                                    }
                                    if ui.small_button("移除").clicked() {
                                        pending_remove_shortcut = Some(index);
                                    }
                                });
                                ui.label(
                                    RichText::new(&shortcut.command)
                                        .small()
                                        .color(palette.text_secondary),
                                );
                                if !shortcut.description.trim().is_empty() {
                                    ui.label(
                                        RichText::new(&shortcut.description)
                                            .small()
                                            .color(palette.text_muted),
                                    );
                                }
                            });
                        ui.add_space(6.0);
                    }
                }

                ui.separator();
                ui.label(
                    RichText::new("最近命令")
                        .strong()
                        .color(palette.text_primary),
                );
                let host_history = self.command_history_for_host(&server.host);
                if host_history.is_empty() {
                    ui.label(RichText::new("这个主机还没有命令历史。").color(palette.text_muted));
                } else {
                    for command in host_history {
                        if ui.button(&command).clicked() {
                            *pending_run_command = Some(command);
                        }
                    }
                }
            }
        });

        if let Some(index) = pending_remove_shortcut {
            self.remove_shortcut(index);
        }
    }

    fn draw_file_transfer_card(&mut self, ui: &mut egui::Ui, palette: &ThemePalette) {
        let active_server = self.tabs.get(self.active_tab).map(|tab| tab.server.clone());
        let mut pending_refresh: Option<(Server, String)> = None;
        let mut pending_download: Option<(Server, String, PathBuf)> = None;
        let mut pending_upload: Option<(Server, PathBuf, String)> = None;
        let mut pending_create_dir: Option<(Server, String)> = None;
        let mut pending_remove: Option<(Server, String, bool)> = None;

        card_frame(palette, palette.panel_soft, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("文件传输")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new("浏览远端目录，上传和下载文件，也能在当前目录里新建与删除。")
                        .small()
                        .color(palette.text_secondary),
                );
                if let Some(label) = &self.file_transfer.busy_label {
                    ui.add_space(6.0);
                    ui.spinner();
                    ui.label(RichText::new(label).small().color(palette.text_secondary));
                }
            });

            let Some(server) = active_server else {
                ui.label(
                    RichText::new("先打开一个标签页，就能开始浏览远端文件与传输内容。")
                        .color(palette.text_muted),
                );
                return;
            };

            let server_changed = self.file_transfer.reset_for_server(&server);
            if server_changed {
                pending_refresh = Some((server.clone(), ".".to_string()));
            }

            ui.label(
                RichText::new(format!("当前目标：{}", server.endpoint()))
                    .small()
                    .color(palette.text_muted),
            );
            if !self.file_transfer.status_text.trim().is_empty() {
                ui.label(
                    RichText::new(&self.file_transfer.status_text)
                        .small()
                        .color(palette.text_secondary),
                );
            }
            ui.add_space(6.0);

            ui.label(
                RichText::new("远端目录")
                    .small()
                    .strong()
                    .color(palette.text_secondary),
            );
            ui.add(
                TextEdit::singleline(&mut self.file_transfer.remote_path)
                    .desired_width(f32::INFINITY)
                    .hint_text("例如：/var/log 或 ."),
            );

            ui.label(
                RichText::new("本地路径")
                    .small()
                    .strong()
                    .color(palette.text_secondary),
            );
            ui.add(
                TextEdit::singleline(&mut self.file_transfer.local_path)
                    .desired_width(f32::INFINITY)
                    .hint_text("上传填本地文件，下载可填目录或完整文件路径"),
            );

            let selected_entry = self.file_transfer.selected_entry().cloned();
            let can_download = selected_entry.as_ref().is_some_and(|entry| !entry.is_dir);

            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(!self.file_transfer.is_busy(), egui::Button::new("刷新目录"))
                    .clicked()
                {
                    pending_refresh =
                        Some((server.clone(), self.file_transfer.remote_path.clone()));
                }

                if ui
                    .add_enabled(!self.file_transfer.is_busy(), egui::Button::new("上一级"))
                    .clicked()
                {
                    pending_refresh = Some((
                        server.clone(),
                        parent_remote_path(&self.file_transfer.remote_path),
                    ));
                }

                if ui
                    .add_enabled(
                        !self.file_transfer.is_busy() && can_download,
                        egui::Button::new("下载所选"),
                    )
                    .clicked()
                {
                    if let Some(entry) = selected_entry.as_ref() {
                        match self.resolve_download_target(entry) {
                            Ok(local_path) => {
                                pending_download =
                                    Some((server.clone(), entry.full_path.clone(), local_path));
                            }
                            Err(error) => self.set_flash(format!("下载准备失败：{error:#}"), true),
                        }
                    }
                }

                if ui
                    .add_enabled(!self.file_transfer.is_busy(), egui::Button::new("上传文件"))
                    .clicked()
                {
                    match self.resolve_upload_target() {
                        Ok((local_path, remote_path)) => {
                            pending_upload = Some((server.clone(), local_path, remote_path));
                        }
                        Err(error) => self.set_flash(format!("上传准备失败：{error:#}"), true),
                    }
                }
            });

            ui.horizontal_wrapped(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.file_transfer.new_directory_name)
                        .hint_text("新建目录名称"),
                );

                if ui
                    .add_enabled(
                        !self.file_transfer.is_busy()
                            && !self.file_transfer.new_directory_name.trim().is_empty(),
                        egui::Button::new("新建目录"),
                    )
                    .clicked()
                {
                    let remote_path = join_sftp_path(
                        self.file_transfer.remote_path.trim(),
                        self.file_transfer.new_directory_name.trim(),
                    );
                    pending_create_dir = Some((server.clone(), remote_path));
                }

                if ui
                    .add_enabled(
                        !self.file_transfer.is_busy() && selected_entry.is_some(),
                        egui::Button::new("删除所选"),
                    )
                    .clicked()
                {
                    if let Some(entry) = selected_entry.as_ref() {
                        pending_remove =
                            Some((server.clone(), entry.full_path.clone(), entry.is_dir));
                    }
                }
            });

            ui.add_space(8.0);
            if self.file_transfer.entries.is_empty() {
                ui.label(
                    RichText::new("目录列表暂时还是空的，点一下“刷新目录”就会拉取远端内容。")
                        .small()
                        .color(palette.text_muted),
                );
            } else {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(280.0)
                    .show(ui, |ui| {
                        for entry in &self.file_transfer.entries {
                            let is_selected = self.file_transfer.selected_remote_path.as_deref()
                                == Some(entry.full_path.as_str());
                            let kind = if entry.is_dir {
                                "目录"
                            } else if entry.is_symlink {
                                "链接"
                            } else {
                                "文件"
                            };
                            let response = egui::Frame::new()
                                .fill(if is_selected {
                                    palette.accent_soft
                                } else {
                                    palette.panel_alt
                                })
                                .stroke(Stroke::new(
                                    1.0,
                                    if is_selected {
                                        palette.accent
                                    } else {
                                        palette.stroke
                                    },
                                ))
                                .corner_radius(CornerRadius::same(14))
                                .inner_margin(Margin::same(10))
                                .show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(
                                            RichText::new(format!(
                                                "{} {}",
                                                if entry.is_dir { "▣" } else { "·" },
                                                entry.name
                                            ))
                                            .strong()
                                            .color(palette.text_primary),
                                        );
                                        badge(
                                            ui,
                                            palette,
                                            kind,
                                            palette.panel_soft,
                                            palette.text_secondary,
                                        );
                                    });
                                    ui.label(
                                        RichText::new(format!(
                                            "大小：{}   权限：{}   修改：{}",
                                            format_bytes(entry.size),
                                            entry.permissions,
                                            format_optional_timestamp(entry.modified_at),
                                        ))
                                        .small()
                                        .color(palette.text_secondary),
                                    );
                                    if entry.is_dir {
                                        ui.label(
                                            RichText::new("双击目录可进入，也可以选中后直接删除。")
                                                .small()
                                                .color(palette.text_muted),
                                        );
                                    }
                                })
                                .response;

                            if response.clicked() {
                                self.file_transfer.selected_remote_path =
                                    Some(entry.full_path.clone());
                            }
                            if response.double_clicked() && entry.is_dir {
                                pending_refresh = Some((server.clone(), entry.full_path.clone()));
                            }

                            ui.add_space(4.0);
                        }
                    });
            }
        });

        if let Some((server, path)) = pending_refresh {
            self.request_file_list(server, Some(path));
        }
        if let Some((server, remote_path, local_path)) = pending_download {
            self.request_file_download(server, remote_path, local_path);
        }
        if let Some((server, local_path, remote_path)) = pending_upload {
            self.request_file_upload(server, local_path, remote_path);
        }
        if let Some((server, path)) = pending_create_dir {
            self.request_create_remote_dir(server, path);
        }
        if let Some((server, path, is_dir)) = pending_remove {
            self.request_remove_remote_path(server, path, is_dir);
        }
    }

    fn draw_script_center_card(
        &mut self,
        ui: &mut egui::Ui,
        pending_run_command: &mut Option<String>,
        palette: &ThemePalette,
    ) {
        let editing = self.editing_script_name.is_some();
        let mut pending_edit: Option<Script> = None;
        let mut pending_delete: Option<String> = None;

        card_frame(palette, palette.panel, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("脚本工坊")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new("把常用 Shell 流程保存下来，随时编辑，也能一键运行。")
                        .small()
                        .color(palette.text_secondary),
                );
            });

            ui.label(
                RichText::new("名称")
                    .small()
                    .strong()
                    .color(palette.text_secondary),
            );
            ui.add(
                TextEdit::singleline(&mut self.script_form.name)
                    .hint_text("例如：deploy-check")
                    .desired_width(f32::INFINITY),
            );

            ui.label(
                RichText::new("说明")
                    .small()
                    .strong()
                    .color(palette.text_secondary),
            );
            ui.add(
                TextEdit::singleline(&mut self.script_form.description)
                    .hint_text("写一句这个脚本要做什么")
                    .desired_width(f32::INFINITY),
            );

            ui.label(
                RichText::new("内容")
                    .small()
                    .strong()
                    .color(palette.text_secondary),
            );
            ui.add_sized(
                [ui.available_width(), 110.0],
                TextEdit::multiline(&mut self.script_form.content)
                    .hint_text("echo hello\nuname -a")
                    .font(TextStyle::Monospace),
            );

            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(if editing {
                        "更新脚本"
                    } else {
                        "保存脚本"
                    })
                    .clicked()
                {
                    self.save_script_from_form();
                }
                if ui.button("运行草稿").clicked() {
                    *pending_run_command = Some(self.script_form.content.clone());
                }
                if editing && ui.button("取消编辑").clicked() {
                    self.editing_script_name = None;
                    self.script_form.reset();
                }
            });

            ui.separator();
            ui.label(
                RichText::new("已保存脚本")
                    .strong()
                    .color(palette.text_primary),
            );

            if self.scripts.is_empty() {
                ui.label(
                    RichText::new("还没有保存脚本。")
                        .small()
                        .color(palette.text_muted),
                );
            } else {
                for script in &self.scripts {
                    egui::Frame::new()
                        .fill(palette.panel_alt)
                        .stroke(Stroke::new(1.0, palette.stroke))
                        .corner_radius(CornerRadius::same(14))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    RichText::new(&script.name)
                                        .strong()
                                        .color(palette.text_primary),
                                );
                                badge(
                                    ui,
                                    palette,
                                    &friendly_time(script.updated_at),
                                    palette.panel_soft,
                                    palette.text_secondary,
                                );
                            });
                            if !script.description.trim().is_empty() {
                                ui.label(
                                    RichText::new(&script.description)
                                        .small()
                                        .color(palette.text_secondary),
                                );
                            }
                            ui.label(
                                RichText::new(script.content.lines().next().unwrap_or_default())
                                    .small()
                                    .color(palette.text_muted),
                            );

                            ui.horizontal_wrapped(|ui| {
                                if ui.button("运行").clicked() {
                                    *pending_run_command = Some(script.content.clone());
                                }
                                if ui.button("加载").clicked() {
                                    pending_edit = Some(script.clone());
                                }
                                if ui.small_button("删除").clicked() {
                                    pending_delete = Some(script.name.clone());
                                }
                            });
                        });
                    ui.add_space(6.0);
                }
            }
        });

        if let Some(script) = pending_edit {
            self.start_editing_script(&script);
        }
        if let Some(name) = pending_delete {
            self.remove_script(&name);
        }
    }

    fn draw_workspace_card(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        palette: &ThemePalette,
    ) {
        card_frame(palette, palette.panel_soft, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("工作台快照")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new("支持导出与导入整套工作台，脚本和主题也会一起带上。")
                        .small()
                        .color(palette.text_secondary),
                );
            });

            ui.label(
                RichText::new("快照路径")
                    .small()
                    .strong()
                    .color(palette.text_secondary),
            );
            ui.add(
                TextEdit::singleline(&mut self.workspace_path)
                    .desired_width(f32::INFINITY)
                    .hint_text("输入工作台快照文件路径"),
            );

            ui.horizontal_wrapped(|ui| {
                if ui.button("导出").clicked() {
                    self.export_workspace_snapshot();
                }
                if ui.button("导入").clicked() {
                    self.import_workspace_snapshot(ctx);
                }
                if ui.button("重置路径").clicked() {
                    self.workspace_path = default_workspace_path().display().to_string();
                }
            });

            ui.label(
                RichText::new("包含内容：服务器、连接历史、命令历史、快捷命令、脚本与主题配色。")
                    .small()
                    .color(palette.text_muted),
            );
        });
    }

    fn draw_audit_card(&mut self, ui: &mut egui::Ui, palette: &ThemePalette) {
        card_frame(palette, palette.panel, 14).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("审计记录")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                if ui.button("刷新").clicked() {
                    self.refresh_audit_entries();
                }
            });
            ui.label(
                RichText::new(audit_log_path().display().to_string())
                    .small()
                    .color(palette.text_muted),
            );

            if self.audit_entries.is_empty() {
                ui.label(
                    RichText::new("暂时还没有审计记录。")
                        .small()
                        .color(palette.text_muted),
                );
            } else {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for entry in &self.audit_entries {
                            egui::Frame::new()
                                .fill(palette.panel_alt)
                                .stroke(Stroke::new(1.0, palette.stroke))
                                .corner_radius(CornerRadius::same(12))
                                .inner_margin(Margin::same(8))
                                .show(ui, |ui| {
                                    ui.label(
                                        RichText::new(entry)
                                            .small()
                                            .monospace()
                                            .color(palette.text_secondary),
                                    );
                                });
                            ui.add_space(4.0);
                        }
                    });
            }
        });
    }

    #[allow(dead_code)]
    fn draw_terminal(
        &mut self,
        ctx: &egui::Context,
        pending_send_command: &mut Option<String>,
        pending_restart_active_tab: &mut bool,
        pending_pin_shortcut: &mut Option<String>,
    ) {
        let palette = self.palette();
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.spacing_mut().item_spacing = vec2(10.0, 10.0);

            if self.tabs.is_empty() {
                self.draw_home_dashboard(ui, &palette);
                return;
            }

            let active_index = self.active_tab;
            let history_commands = self
                .tabs
                .get(active_index)
                .map(|tab| self.command_history_for_host(&tab.server.host))
                .unwrap_or_default();

            let title_font = self.display_font(28.0);
            let mut pending_interrupt_echo = false;
            let tab = &mut self.tabs[active_index];
            tab.unseen_output = false;

            card_frame(&palette, palette.panel, 14).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(&tab.title)
                            .font(title_font.clone())
                            .color(palette.text_primary),
                    );
                    badge(
                        ui,
                        &palette,
                        &tab.status_text,
                        tab.status_color(&palette).linear_multiply(0.18),
                        tab.status_color(&palette),
                    );
                });

                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    stat_chip(ui, &palette, "目标", tab.server.endpoint());
                    stat_chip(ui, &palette, "会话", format!("#{}", tab.id));
                    stat_chip(ui, &palette, "尝试", tab.connection_attempt.to_string());
                    stat_chip(ui, &palette, "重连", tab.reconnect_count.to_string());
                    stat_chip(ui, &palette, "在线时长", tab.uptime_text());
                    if let Some(delay_secs) = tab.retry_delay_secs {
                        stat_chip(ui, &palette, "退避", format!("{delay_secs}s"));
                    }
                });

                ui.label(
                    RichText::new(tab.server.connection_policy.summary())
                        .small()
                        .color(palette.text_secondary),
                );
            });

            let available_for_terminal = ui.available_height();
            let terminal_height = (available_for_terminal - 118.0).max(260.0);

            let full_size = ui.available_size_before_wrap();
            // Approximate terminal geometry from the drawn region so remote full-screen apps resize
            // naturally when the window changes.
            let cols = ((full_size.x.max(480.0) / 8.4).floor() as u32).max(DEFAULT_TERMINAL_COLS);
            let rows =
                ((terminal_height.max(320.0) / 18.0).floor() as u32).max(DEFAULT_TERMINAL_ROWS);
            let desired = (cols, rows);
            if tab.last_terminal_size != Some(desired) {
                match tab.session.resize(
                    desired.0,
                    desired.1,
                    full_size.x as u32,
                    terminal_height as u32,
                ) {
                    Ok(()) => tab.last_terminal_size = Some(desired),
                    Err(error) => tab.push_system_message(&format!("调整终端尺寸失败：{error}")),
                }
            }

            egui::Frame::new()
                .fill(palette.terminal_bg)
                .stroke(Stroke::new(1.2, palette.terminal_border))
                .corner_radius(CornerRadius::same(20))
                .inner_margin(Margin::same(14))
                .show(ui, |ui| {
                    ui.set_min_height(terminal_height);
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(tab.auto_scroll)
                        .auto_shrink([false, false])
                        .max_height(terminal_height)
                        .show(ui, |ui| {
                            ui.add_sized(
                                [ui.available_width(), terminal_height],
                                TextEdit::multiline(&mut tab.terminal_content)
                                    .font(TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .frame(false)
                                    .interactive(true)
                                    .text_color(palette.terminal_text),
                            );
                        });
                });

            card_frame(&palette, palette.panel_soft, 12).show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut tab.auto_scroll, "跟随输出");
                    if ui.button("清空终端").clicked() {
                        tab.terminal_content.clear();
                    }
                    if ui.button("重连").clicked() {
                        match tab.state {
                            TabState::Disconnected | TabState::Failed => {
                                *pending_restart_active_tab = true;
                            }
                            TabState::Connecting | TabState::Reconnecting | TabState::Connected => {
                                match tab.session.reconnect_now() {
                                    Ok(()) => tab.push_system_message("已发出重连请求。"),
                                    Err(error) => tab
                                        .push_system_message(&format!("发起重连请求失败：{error}")),
                                }
                            }
                        }
                    }
                    if ui.button("发送 Ctrl+C").clicked() {
                        match tab.session.interrupt() {
                            Ok(()) => pending_interrupt_echo = true,
                            Err(error) => {
                                tab.push_system_message(&format!("发送 Ctrl+C 失败：{error}"))
                            }
                        }
                    }
                    if ui.button("断开连接").clicked() {
                        match tab.session.disconnect() {
                            Ok(()) => tab.push_system_message("已发出断开请求。"),
                            Err(error) => {
                                tab.push_system_message(&format!("发起断开请求失败：{error}"))
                            }
                        }
                    }
                });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let response = ui.add(
                        TextEdit::singleline(&mut tab.input_buffer)
                            .hint_text("输入命令后按回车发送")
                            .desired_width(f32::INFINITY),
                    );

                    if response.changed() {
                        tab.history_cursor = None;
                    }
                    if response.has_focus() {
                        if ui.input(|input| input.key_pressed(egui::Key::ArrowUp)) {
                            tab.navigate_history(&history_commands, true);
                        }
                        if ui.input(|input| input.key_pressed(egui::Key::ArrowDown)) {
                            tab.navigate_history(&history_commands, false);
                        }
                    }

                    let enter_pressed = response.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter));
                    if enter_pressed || ui.button("发送").clicked() {
                        *pending_send_command = Some(tab.input_buffer.clone());
                    }

                    if ui.button("收藏").clicked() {
                        *pending_pin_shortcut = Some(tab.input_buffer.clone());
                    }
                });
            });
            if pending_interrupt_echo {
                self.echo_terminal_interrupt(active_index);
            }
        });
    }

    fn draw_home_dashboard(&self, ui: &mut egui::Ui, palette: &ThemePalette) {
        card_frame(palette, palette.panel, 18).show(ui, |ui| {
            ui.add_space(12.0);
            ui.label(
                RichText::new("现代 SSH 客户端")
                    .font(self.display_font(40.0))
                    .color(palette.text_primary),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "用于建立 SSH 连接，替代 PuTTY、Termius、SecureCRT 和 macOS Terminal.app。\
                     从左侧打开一台已保存的服务器，或者先新建连接，再进入终端、SFTP 和连接资料视图。",
                )
                .color(palette.text_secondary),
            );
            ui.add_space(12.0);

            ui.horizontal_wrapped(|ui| {
                stat_chip(ui, palette, "已保存服务器", self.servers.len().to_string());
                stat_chip(
                    ui,
                    palette,
                    "历史分组",
                    self.grouped_connection_history().len().to_string(),
                );
                stat_chip(
                    ui,
                    palette,
                    "主题",
                    self.settings.theme_preset.label().to_string(),
                );
                stat_chip(
                    ui,
                    palette,
                    "同步",
                    self.logged_in_user
                        .as_deref()
                        .unwrap_or("未登录")
                        .to_string(),
                );
            });
        });

        ui.add_space(10.0);
        ui.columns(2, |columns| {
            card_frame(palette, palette.panel_soft, 14).show(&mut columns[0], |ui| {
                ui.label(
                    RichText::new("这次升级")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new(
                        "现在有更可爱的主题配色、分组连接历史、账号同步快照、更完整的服务器管理，以及一键收藏命令。",
                    )
                    .color(palette.text_secondary),
                );
            });

            card_frame(palette, palette.panel_soft, 14).show(&mut columns[1], |ui| {
                ui.label(
                    RichText::new("建议先这样用")
                        .font(self.display_font(24.0))
                        .color(palette.text_primary),
                );
                ui.label(
                    RichText::new(
                        "1. 先保存或编辑一台服务器。\n2. 登录同步账号。\n3. 选一个喜欢的主题。\n4. 打开标签页并收藏常用命令。",
                    )
                    .color(palette.text_secondary),
                );
            });
        });
    }

    fn paint_background(&self, ctx: &egui::Context) {
        let palette = self.palette();
        let rect = ctx.content_rect();
        let painter = ctx.layer_painter(egui::LayerId::background());

        if let Some(texture) = &self.background_texture {
            painter.image(
                texture.id(),
                rect,
                egui::Rect::from_min_max(pos2(0.0, 0.0), pos2(1.0, 1.0)),
                Color32::from_rgba_premultiplied(255, 255, 255, 178),
            );
        }

        painter.rect_filled(
            rect,
            0.0,
            Color32::from_rgba_premultiplied(5, 10, 18, 34),
        );

        let mut overlay = Mesh::default();
        let base = overlay.vertices.len() as u32;
        overlay.colored_vertex(
            rect.left_top(),
            Color32::from_rgba_premultiplied(
                palette.background_top.r(),
                palette.background_top.g(),
                palette.background_top.b(),
                126,
            ),
        );
        overlay.colored_vertex(
            rect.right_top(),
            Color32::from_rgba_premultiplied(
                palette.background_top.r(),
                palette.background_top.g(),
                palette.background_top.b(),
                84,
            ),
        );
        overlay.colored_vertex(
            rect.right_bottom(),
            Color32::from_rgba_premultiplied(
                palette.background_bottom.r(),
                palette.background_bottom.g(),
                palette.background_bottom.b(),
                118,
            ),
        );
        overlay.colored_vertex(
            rect.left_bottom(),
            Color32::from_rgba_premultiplied(
                palette.background_bottom.r(),
                palette.background_bottom.g(),
                palette.background_bottom.b(),
                138,
            ),
        );
        overlay.add_triangle(base, base + 1, base + 2);
        overlay.add_triangle(base, base + 2, base + 3);
        painter.add(egui::Shape::mesh(overlay));

        painter.circle_filled(
            pos2(
                rect.left() + rect.width() * 0.82,
                rect.top() + rect.height() * 0.15,
            ),
            rect.width().min(rect.height()) * 0.24,
            palette.blossom.linear_multiply(1.12),
        );
        painter.circle_filled(
            pos2(
                rect.left() + rect.width() * 0.16,
                rect.top() + rect.height() * 0.2,
            ),
            rect.width().min(rect.height()) * 0.16,
            palette.mist.linear_multiply(1.45),
        );
        painter.circle_filled(
            pos2(
                rect.left() + rect.width() * 0.52,
                rect.top() + rect.height() * 0.82,
            ),
            rect.width().min(rect.height()) * 0.22,
            palette.blossom.linear_multiply(0.72),
        );
        painter.circle_filled(
            pos2(
                rect.left() + rect.width() * 0.3,
                rect.top() + rect.height() * 0.62,
            ),
            rect.width().min(rect.height()) * 0.11,
            palette.accent_soft.linear_multiply(1.25),
        );

        painter.line_segment(
            [
                pos2(rect.left() + 48.0, rect.top() + 64.0),
                pos2(rect.right() - 120.0, rect.top() + 112.0),
            ],
            Stroke::new(1.0, palette.stroke.linear_multiply(0.42)),
        );
        painter.line_segment(
            [
                pos2(rect.left() + 96.0, rect.bottom() - 104.0),
                pos2(rect.right() - 48.0, rect.bottom() - 72.0),
            ],
            Stroke::new(1.0, palette.stroke.linear_multiply(0.3)),
        );
    }
}

impl Drop for App {
    fn drop(&mut self) {
        for tab in &self.tabs {
            let _ = tab.session.disconnect();
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_sessions();
        self.poll_file_transfer_events();
        if self
            .flash_message
            .as_ref()
            .is_some_and(|message| message.created_at.elapsed() > Duration::from_secs(5))
        {
            self.flash_message = None;
        }
        if self.background_texture.is_none() {
            self.background_texture = load_background_texture(ctx);
        }
        apply_theme(ctx, self.settings.theme_preset);
        self.paint_background(ctx);
        let repaint_ms = if self.file_transfer.is_busy()
            || self
                .tabs
                .iter()
                .any(|tab| matches!(tab.state, TabState::Connecting | TabState::Reconnecting))
        {
            60
        } else if self.tabs.is_empty() {
            180
        } else {
            100
        };
        ctx.request_repaint_after(Duration::from_millis(repaint_ms));

        let mut pending_connect = None;
        let mut pending_close = None;
        let mut pending_run_command = None;
        let mut pending_send_command = None;
        let mut pending_restart_active_tab = false;
        let mut pending_pin_shortcut = None;

        self.draw_shell_top_bar(ctx);
        if self.app_page == AppPage::Connections {
            self.draw_shell_sidebar(ctx, &mut pending_connect);
        }
        if self.app_page == AppPage::Terminal {
            self.draw_global_tabs_bar_modern(ctx, &mut pending_close);
        }
        self.draw_workspace(
            ctx,
            &mut pending_connect,
            &mut pending_run_command,
            &mut pending_send_command,
            &mut pending_restart_active_tab,
            &mut pending_pin_shortcut,
        );
        if self.has_blocking_modal_open() {
            self.draw_modal_backdrop(ctx);
        }
        self.draw_sync_dialog_modal(ctx);
        self.draw_server_editor_dialog_modal(ctx);
        self.draw_auth_prompt_modal(ctx);
        self.draw_delete_server_dialog(ctx);
        self.toasts.show(ctx);

        if let Some(server) = pending_connect {
            self.connect_to_server(server);
        }
        if let Some(command) = pending_run_command {
            self.send_active_command(command);
        }
        if let Some(command) = pending_send_command {
            self.send_active_command(command);
        }
        if let Some(command) = pending_pin_shortcut {
            self.pin_command_as_shortcut(&command);
        }
        if let Some(index) = pending_close {
            self.close_tab(index);
        }
        if pending_restart_active_tab && !self.tabs.is_empty() {
            self.restart_tab_session(self.active_tab);
        }
    }
}

fn install_fonts(ctx: &egui::Context) -> bool {
    let mut fonts = FontDefinitions::default();
    let mut has_body_font = false;
    let mut has_display_font = false;
    let mut has_terminal_font = false;

    // Prefer system CJK fonts so the app can render Chinese labels without bundling assets.
    if let Some(font) = load_font_data(&[
        ("C:\\Windows\\Fonts\\msyh.ttc", 0),
        ("C:\\Windows\\Fonts\\segoeui.ttf", 0),
        ("/System/Library/Fonts/PingFang.ttc", 0),
        ("/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc", 0),
    ]) {
        fonts
            .font_data
            .insert(BODY_FONT_NAME.to_owned(), Arc::new(font));
        if let Some(family) = fonts.families.get_mut(&FontFamily::Proportional) {
            family.insert(0, BODY_FONT_NAME.to_owned());
        }
        has_body_font = true;
    }

    if let Some(font) = load_font_data(&[
        ("C:\\Windows\\Fonts\\CascadiaMono.ttf", 0),
        ("C:\\Windows\\Fonts\\consola.ttf", 0),
        ("C:\\Windows\\Fonts\\msyh.ttc", 0),
        ("/System/Library/Fonts/SFNSMono.ttf", 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
    ]) {
        fonts
            .font_data
            .insert(TERMINAL_FONT_NAME.to_owned(), Arc::new(font));
        has_terminal_font = true;
    }

    if let Some(font) = load_font_data(&[
        ("C:\\Windows\\Fonts\\SitkaI.ttc", 0),
        ("C:\\Windows\\Fonts\\simkai.ttf", 0),
        ("/System/Library/Fonts/Supplemental/Kaiti.ttc", 0),
        ("/usr/share/fonts/truetype/arphic/ukai.ttc", 0),
    ]) {
        // A second family lets headings lean into the "ink painting" mood without affecting body text.
        fonts
            .font_data
            .insert(DISPLAY_FONT_NAME.to_owned(), Arc::new(font));

        let mut display_family = vec![DISPLAY_FONT_NAME.to_owned()];
        if has_body_font {
            display_family.push(BODY_FONT_NAME.to_owned());
        } else if let Some(fallbacks) = fonts.families.get(&FontFamily::Proportional) {
            display_family.extend(fallbacks.clone());
        }

        fonts
            .families
            .insert(FontFamily::Name(DISPLAY_FONT_NAME.into()), display_family);
        has_display_font = true;
    }

    let mut terminal_family = Vec::new();
    if has_terminal_font {
        terminal_family.push(TERMINAL_FONT_NAME.to_owned());
    }
    if has_body_font {
        terminal_family.push(BODY_FONT_NAME.to_owned());
    }
    if let Some(defaults) = fonts.families.get(&FontFamily::Monospace) {
        terminal_family.extend(defaults.clone());
    }
    if !terminal_family.is_empty() {
        fonts
            .families
            .insert(FontFamily::Name(TERMINAL_FONT_NAME.into()), terminal_family.clone());
        fonts
            .families
            .insert(FontFamily::Monospace, terminal_family);
    }

    ctx.set_fonts(fonts);
    has_display_font
}

fn load_font_data(candidates: &[(&str, u32)]) -> Option<FontData> {
    for (path, index) in candidates {
        if !Path::new(path).exists() {
            continue;
        }

        if let Ok(bytes) = fs::read(path) {
            // TTC collections need an explicit face index, so callers pass both path and index.
            let mut data = FontData::from_owned(bytes);
            data.index = *index;
            return Some(data);
        }
    }

    None
}

fn load_background_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let image = image::load_from_memory(BACKGROUND_IMAGE_BYTES)
        .ok()?
        .to_rgba8();
    let size = [image.width() as usize, image.height() as usize];
    let pixels = image.into_raw();
    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);

    Some(ctx.load_texture(
        "workspace_background",
        color_image,
        egui::TextureOptions::LINEAR,
    ))
}

struct ParsedSshTarget {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

fn parse_ssh_target(target: &str) -> ParsedSshTarget {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return ParsedSshTarget {
            user: None,
            host: String::new(),
            port: None,
        };
    }

    let (user, host_port) = match trimmed.rsplit_once('@') {
        Some((user, host_port)) if !user.trim().is_empty() && !host_port.trim().is_empty() => {
            (Some(user.trim().to_string()), host_port.trim())
        }
        _ => (None, trimmed),
    };

    let mut host = host_port.trim().to_string();
    let mut port = None;

    if let Some(bracketed) = host_port.strip_prefix('[') {
        if let Some(closing) = bracketed.find(']') {
            host = bracketed[..closing].trim().to_string();
            let remainder = &bracketed[closing + 1..];
            if let Some(port_text) = remainder.strip_prefix(':') {
                if let Ok(value) = port_text.trim().parse::<u16>() {
                    port = Some(value);
                }
            }
        }
    } else if host_port.matches(':').count() == 1 {
        if let Some((host_part, port_part)) = host_port.rsplit_once(':') {
            if let Ok(value) = port_part.trim().parse::<u16>() {
                host = host_part.trim().to_string();
                port = Some(value);
            }
        }
    }

    ParsedSshTarget { user, host, port }
}

fn terminal_text_from_bytes(output: &[u8]) -> String {
    let text = String::from_utf8_lossy(output);
    let mut cleaned = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        match chars[index] {
            '\u{1b}' => {
                index += 1;
                if index >= chars.len() {
                    break;
                }

                match chars[index] {
                    '[' => {
                        index += 1;
                        while index < chars.len() {
                            let ch = chars[index];
                            index += 1;
                            if ('@'..='~').contains(&ch) {
                                break;
                            }
                        }
                    }
                    ']' => {
                        index += 1;
                        while index < chars.len() {
                            match chars[index] {
                                '\u{0007}' => {
                                    index += 1;
                                    break;
                                }
                                '\u{1b}'
                                    if chars.get(index + 1).copied() == Some('\\') =>
                                {
                                    index += 2;
                                    break;
                                }
                                _ => index += 1,
                            }
                        }
                    }
                    _ => {
                        index += 1;
                    }
                }
            }
            '\r' => {
                if chars.get(index + 1).copied() == Some('\n') {
                    cleaned.push('\n');
                    index += 2;
                } else {
                    index += 1;
                }
            }
            ch if ch.is_control() && ch != '\n' && ch != '\t' => {
                index += 1;
            }
            ch => {
                cleaned.push(ch);
                index += 1;
            }
        }
    }

    cleaned
}

fn build_terminal_layout_job(
    text: &str,
    palette: &ThemePalette,
    identity: &str,
    show_cursor: bool,
) -> LayoutJob {
    let font_id = FontId::new(13.0, FontFamily::Name(TERMINAL_FONT_NAME.into()));
    let mut job = LayoutJob::default();
    let body_color = palette.terminal_text;

    for line in text.split_inclusive('\n') {
        append_terminal_line(&mut job, line, palette, identity, &font_id, body_color);
    }

    if !text.is_empty() && !text.ends_with('\n') {
        append_terminal_line(&mut job, "", palette, identity, &font_id, body_color);
    }

    if show_cursor {
        job.append(
            "|",
            0.0,
            TextFormat {
                font_id: font_id.clone(),
                color: palette.success,
                line_height: Some(13.4),
                ..Default::default()
            },
        );
    }

    job
}

fn append_terminal_line(
    job: &mut LayoutJob,
    line: &str,
    palette: &ThemePalette,
    identity: &str,
    font_id: &FontId,
    default_color: Color32,
) {
    if line.is_empty() {
        return;
    }

    let content = line.strip_suffix('\n').unwrap_or(line);
    let content_lower = content.to_ascii_lowercase();

    if content.trim_start().starts_with("# ") {
        append_terminal_span(job, line, font_id, palette.text_muted);
        return;
    }

    let line_color = if ["error", "failed", "denied", "panic", "traceback"]
        .iter()
        .any(|needle| content_lower.contains(needle))
    {
        palette.danger
    } else if ["warn", "warning"].iter().any(|needle| content_lower.contains(needle)) {
        palette.warning
    } else if ["success", "complete", "done", "started", "ready"]
        .iter()
        .any(|needle| content_lower.contains(needle))
    {
        palette.success
    } else {
        default_color
    };

    let mut token = String::new();
    for ch in content.chars() {
        if ch.is_whitespace() {
            if !token.is_empty() {
                let token_color =
                    classify_terminal_token(&token, line_color, palette, identity, content);
                append_terminal_span(job, &token, font_id, token_color);
                token.clear();
            }
            let whitespace = ch.to_string();
            append_terminal_span(job, &whitespace, font_id, line_color);
        } else {
            token.push(ch);
        }
    }

    if !token.is_empty() {
        let token_color = classify_terminal_token(&token, line_color, palette, identity, content);
        append_terminal_span(job, &token, font_id, token_color);
    }

    if line.ends_with('\n') {
        append_terminal_span(job, "\n", font_id, line_color);
    }
}

fn classify_terminal_token(
    token: &str,
    line_color: Color32,
    palette: &ThemePalette,
    identity: &str,
    full_line: &str,
) -> Color32 {
    let trimmed = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']'));
    if trimmed.is_empty() {
        return line_color;
    }

    let lower = trimmed.to_ascii_lowercase();
    let prompt_like = full_line.trim_start().starts_with(identity)
        || full_line.trim_start().starts_with("root@")
        || full_line.trim_start().contains("@");

    if trimmed == identity || lower.starts_with("root@") || lower.contains("@localhost") {
        return palette.success;
    }
    if prompt_like && matches!(trimmed, "$" | "#" | ">" | "%") {
        return palette.warning;
    }
    if trimmed.ends_with(':') && trimmed.len() > 1 {
        return palette.accent;
    }
    if trimmed.starts_with("~/") || trimmed.starts_with('/') || trimmed.starts_with("./") {
        return palette.accent;
    }
    if trimmed.starts_with("--") || (trimmed.starts_with('-') && trimmed.len() > 1) {
        return palette.warning;
    }
    if lower.starts_with("0x") || lower.chars().all(|ch| ch.is_ascii_digit()) {
        return palette.warning;
    }
    if trimmed.starts_with('"') || trimmed.starts_with('\'') {
        return palette.text_secondary;
    }
    if matches!(
        lower.as_str(),
        "ssh"
            | "sudo"
            | "cd"
            | "ls"
            | "cat"
            | "grep"
            | "find"
            | "tail"
            | "less"
            | "more"
            | "vim"
            | "nano"
            | "systemctl"
            | "journalctl"
            | "docker"
            | "kubectl"
            | "git"
            | "cargo"
            | "rustc"
            | "python"
            | "python3"
            | "pip"
            | "npm"
            | "pnpm"
            | "yarn"
            | "chmod"
            | "chown"
            | "mkdir"
            | "rm"
            | "cp"
            | "mv"
            | "top"
            | "htop"
            | "uname"
            | "whoami"
            | "echo"
            | "export"
    ) {
        return palette.success;
    }

    line_color
}

fn append_terminal_span(job: &mut LayoutJob, text: &str, font_id: &FontId, color: Color32) {
    if text.is_empty() {
        return;
    }

    job.append(
        text,
        0.0,
        TextFormat {
            font_id: font_id.clone(),
            color,
            line_height: Some(13.4),
            ..Default::default()
        },
    );
}

fn terminal_key_bytes(key: egui::Key, modifiers: egui::Modifiers) -> Option<Vec<u8>> {
    if modifiers.ctrl {
        if let Some(control_byte) = control_key_byte(key) {
            return Some(vec![control_byte]);
        }
    }

    let bytes = match key {
        egui::Key::Enter => vec![b'\r'],
        egui::Key::Tab if modifiers.shift => b"\x1b[Z".to_vec(),
        egui::Key::Tab => vec![b'\t'],
        egui::Key::Backspace => vec![0x7f],
        egui::Key::Escape => vec![0x1b],
        egui::Key::ArrowUp => b"\x1b[A".to_vec(),
        egui::Key::ArrowDown => b"\x1b[B".to_vec(),
        egui::Key::ArrowRight => b"\x1b[C".to_vec(),
        egui::Key::ArrowLeft => b"\x1b[D".to_vec(),
        egui::Key::Home => b"\x1b[H".to_vec(),
        egui::Key::End => b"\x1b[F".to_vec(),
        egui::Key::Insert => b"\x1b[2~".to_vec(),
        egui::Key::Delete => b"\x1b[3~".to_vec(),
        egui::Key::PageUp => b"\x1b[5~".to_vec(),
        egui::Key::PageDown => b"\x1b[6~".to_vec(),
        _ => return None,
    };

    if modifiers.alt {
        let mut prefixed = vec![0x1b];
        prefixed.extend(bytes);
        Some(prefixed)
    } else {
        Some(bytes)
    }
}

fn control_key_byte(key: egui::Key) -> Option<u8> {
    match key {
        egui::Key::A => Some(0x01),
        egui::Key::B => Some(0x02),
        egui::Key::C => Some(0x03),
        egui::Key::D => Some(0x04),
        egui::Key::E => Some(0x05),
        egui::Key::F => Some(0x06),
        egui::Key::G => Some(0x07),
        egui::Key::H => Some(0x08),
        egui::Key::I => Some(0x09),
        egui::Key::J => Some(0x0a),
        egui::Key::K => Some(0x0b),
        egui::Key::L => Some(0x0c),
        egui::Key::M => Some(0x0d),
        egui::Key::N => Some(0x0e),
        egui::Key::O => Some(0x0f),
        egui::Key::P => Some(0x10),
        egui::Key::Q => Some(0x11),
        egui::Key::R => Some(0x12),
        egui::Key::S => Some(0x13),
        egui::Key::T => Some(0x14),
        egui::Key::U => Some(0x15),
        egui::Key::V => Some(0x16),
        egui::Key::W => Some(0x17),
        egui::Key::X => Some(0x18),
        egui::Key::Y => Some(0x19),
        egui::Key::Z => Some(0x1a),
        egui::Key::Space => Some(0x00),
        _ => None,
    }
}

fn default_workspace_path() -> PathBuf {
    data_dir().join("workspace_snapshot.json")
}

fn default_transfer_path() -> PathBuf {
    temp_dir()
}

fn load_recent_audit_entries(limit: usize) -> Vec<String> {
    let data = match fs::read_to_string(audit_log_path()) {
        Ok(data) => data,
        Err(_) => match fs::read_to_string(legacy_audit_log_path()) {
            Ok(data) => data,
            Err(_) => return Vec::new(),
        },
    };

    // Read from the end so the UI can show the latest audit activity without parsing the whole file.
    let mut lines: Vec<String> = data
        .lines()
        .rev()
        .take(limit)
        .map(|line| line.to_string())
        .collect();
    lines.reverse();
    lines
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn apply_theme(ctx: &egui::Context, preset: ThemePreset) {
    let palette = ThemePalette::from_preset(preset);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = Color32::from_rgba_premultiplied(0, 0, 0, 0);
    style.visuals.window_fill = palette.panel.linear_multiply(1.08);
    style.visuals.window_stroke = Stroke::new(0.9, palette.stroke.linear_multiply(0.72));
    style.visuals.window_shadow = Shadow {
        offset: [0, 18],
        blur: 48,
        spread: 0,
        color: palette.shadow,
    };
    style.visuals.popup_shadow = Shadow {
        offset: [0, 14],
        blur: 36,
        spread: 0,
        color: palette.shadow,
    };
    style.visuals.window_corner_radius = CornerRadius::same(18);
    style.visuals.menu_corner_radius = CornerRadius::same(16);
    style.visuals.extreme_bg_color = palette.panel;
    style.visuals.faint_bg_color = palette.panel_soft;
    style.visuals.code_bg_color = palette.panel_soft;
    style.visuals.override_text_color = Some(palette.text_primary);
    style.visuals.widgets.noninteractive.bg_fill = palette.panel;
    style.visuals.widgets.noninteractive.weak_bg_fill = palette.panel_soft;
    style.visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, palette.stroke);
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, palette.text_primary);
    style.visuals.widgets.noninteractive.corner_radius = CornerRadius::same(16);
    style.visuals.widgets.inactive.bg_fill = palette.panel_soft;
    style.visuals.widgets.inactive.weak_bg_fill = palette.panel_soft;
    style.visuals.widgets.inactive.bg_stroke =
        Stroke::new(0.9, palette.stroke.linear_multiply(0.7));
    style.visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, palette.text_primary);
    style.visuals.widgets.inactive.corner_radius = CornerRadius::same(16);
    style.visuals.widgets.hovered.bg_fill = palette.panel_alt;
    style.visuals.widgets.hovered.weak_bg_fill = palette.panel_alt;
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.2, palette.accent);
    style.visuals.widgets.hovered.fg_stroke = Stroke::new(1.2, palette.text_primary);
    style.visuals.widgets.hovered.corner_radius = CornerRadius::same(16);
    style.visuals.widgets.active.bg_fill = palette.accent_soft;
    style.visuals.widgets.active.weak_bg_fill = palette.accent_soft;
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.2, palette.accent);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.2, palette.text_primary);
    style.visuals.widgets.active.corner_radius = CornerRadius::same(16);
    style.visuals.widgets.open.bg_fill = palette.panel_soft;
    style.visuals.widgets.open.weak_bg_fill = palette.panel_soft;
    style.visuals.widgets.open.bg_stroke = Stroke::new(1.0, palette.stroke);
    style.visuals.widgets.open.fg_stroke = Stroke::new(1.0, palette.text_primary);
    style.visuals.widgets.open.corner_radius = CornerRadius::same(16);
    style.visuals.selection.bg_fill = palette.accent_soft;
    style.visuals.selection.stroke = Stroke::new(1.0, palette.accent);
    style.visuals.hyperlink_color = palette.accent;
    style.visuals.text_cursor.stroke = Stroke::new(1.8, palette.accent);

    style.spacing.item_spacing = vec2(10.0, 10.0);
    style.spacing.button_padding = vec2(13.0, 8.0);
    style.spacing.menu_margin = Margin::same(10);
    style.spacing.window_margin = Margin::same(16);
    style.spacing.indent = 16.0;
    style.spacing.scroll.bar_width = 8.0;
    style.spacing.scroll.floating_allocated_width = 5.0;
    style.spacing.scroll.bar_inner_margin = 4.0;

    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(16.0, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(15.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(13.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(24.0, FontFamily::Name(DISPLAY_FONT_NAME.into())),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(13.5, FontFamily::Name(TERMINAL_FONT_NAME.into())),
    );

    ctx.set_style(style);
}

fn shell_pill(
    ui: &mut egui::Ui,
    palette: &ThemePalette,
    label: &str,
    selected: bool,
    padding_x: i8,
    padding_y: i8,
) -> egui::Response {
    egui::Frame::new()
        .fill(if selected {
            palette.panel_alt.linear_multiply(1.2)
        } else {
            palette.panel.linear_multiply(0.9)
        })
        .stroke(Stroke::new(
            if selected { 1.45 } else { 0.95 },
            if selected {
                palette.accent
            } else {
                palette.stroke.linear_multiply(0.64)
            },
        ))
        .corner_radius(CornerRadius::same(99))
        .inner_margin(Margin::symmetric(padding_x + 1, padding_y + 1))
        .show(ui, |ui| {
            ui.add(
                egui::Button::new(
                    RichText::new(label)
                        .small()
                        .strong()
                        .color(if selected {
                            palette.text_primary
                        } else {
                            palette.text_secondary
                        }),
                )
                .frame(false),
            )
        })
        .inner
}

fn terminal_toolbar_button(
    ui: &mut egui::Ui,
    palette: &ThemePalette,
    label: &str,
) -> egui::Response {
    ui.add(
        egui::Button::new(
            RichText::new(label)
                .small()
                .color(palette.text_secondary),
        )
        .frame(false),
    )
}

fn sidebar_nav_button(
    ui: &mut egui::Ui,
    palette: &ThemePalette,
    label: &str,
    meta: &str,
    selected: bool,
) -> egui::Response {
    egui::Frame::new()
        .fill(if selected {
            palette.panel_alt
        } else {
            Color32::TRANSPARENT
        })
        .stroke(Stroke::new(
            1.0,
            if selected {
                palette.accent
            } else {
                Color32::TRANSPARENT
            },
        ))
        .corner_radius(CornerRadius::same(18))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).strong().color(palette.text_primary));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(meta).small().color(palette.text_muted));
                });
            })
            .response
        })
        .inner
}

fn host_card_tint(palette: &ThemePalette, index: usize) -> Color32 {
    match index % 4 {
        0 => palette.accent,
        1 => palette.warning,
        2 => palette.success,
        _ => palette.text_secondary,
    }
}

fn host_card_symbol(server: &Server) -> &'static str {
    match server.auth_method {
        AuthMethod::Password => "密码",
        AuthMethod::PrivateKey => "密钥",
    }
}

fn host_card_pill_label(server: &Server) -> &'static str {
    match server.auth_method {
        AuthMethod::Password => "SSH",
        AuthMethod::PrivateKey => "KEY",
    }
}

fn host_card_meta(server: &Server) -> &'static str {
    match server.auth_method {
        AuthMethod::Password => "密码认证",
        AuthMethod::PrivateKey => "SSH · 密钥",
    }
}

fn card_frame(palette: &ThemePalette, fill: Color32, padding: i8) -> egui::Frame {
    egui::Frame::new()
        .fill(fill.linear_multiply(1.06))
        .stroke(Stroke::new(1.0, palette.stroke.linear_multiply(0.72)))
        .corner_radius(CornerRadius::same(24))
        .inner_margin(Margin::same(padding))
        .shadow(Shadow {
            offset: [0, 22],
            blur: 56,
            spread: 1,
            color: palette.shadow,
        })
}

fn glass_window_frame(palette: &ThemePalette) -> egui::Frame {
    egui::Frame::new()
        .fill(palette.panel.linear_multiply(1.12))
        .stroke(Stroke::new(1.0, palette.stroke.linear_multiply(0.78)))
        .corner_radius(CornerRadius::same(26))
        .inner_margin(Margin::same(20))
        .shadow(Shadow {
            offset: [0, 22],
            blur: 64,
            spread: 1,
            color: palette.shadow,
        })
}

fn stat_chip(ui: &mut egui::Ui, palette: &ThemePalette, label: &str, value: impl ToString) {
    egui::Frame::new()
        .fill(palette.panel_alt.linear_multiply(1.04))
        .stroke(Stroke::new(1.0, palette.stroke.linear_multiply(0.72)))
        .corner_radius(CornerRadius::same(16))
        .inner_margin(Margin::symmetric(11, 8))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(label)
                        .small()
                        .strong()
                        .color(palette.text_secondary),
                );
                ui.label(
                    RichText::new(value.to_string())
                        .small()
                        .color(palette.text_primary),
                );
            });
        });
}

fn badge(
    ui: &mut egui::Ui,
    palette: &ThemePalette,
    text: &str,
    fill: Color32,
    text_color: Color32,
) {
    egui::Frame::new()
        .fill(fill.linear_multiply(1.04))
        .stroke(Stroke::new(1.0, palette.stroke.linear_multiply(0.72)))
        .corner_radius(CornerRadius::same(99))
        .inner_margin(Margin::symmetric(11, 7))
        .show(ui, |ui| {
            ui.label(RichText::new(text).small().strong().color(text_color));
        });
}

fn rich_info_card(
    ui: &mut egui::Ui,
    palette: &ThemePalette,
    eyebrow: &str,
    title: &str,
    body: &str,
) {
    card_frame(palette, palette.panel_soft, 16).show(ui, |ui| {
        badge(
            ui,
            palette,
            eyebrow,
            palette.accent_soft,
            palette.text_primary,
        );
        ui.add_space(10.0);
        ui.label(RichText::new(title).strong().color(palette.text_primary));
        ui.add_space(4.0);
        ui.label(RichText::new(body).small().color(palette.text_secondary));
    });
}

fn rich_step_row(
    ui: &mut egui::Ui,
    palette: &ThemePalette,
    index: &str,
    title: &str,
    body: &str,
) {
    card_frame(palette, palette.panel, 14).show(ui, |ui| {
        ui.horizontal(|ui| {
            egui::Frame::new()
                .fill(palette.accent_soft)
                .stroke(Stroke::new(1.0, palette.accent))
                .corner_radius(CornerRadius::same(99))
                .inner_margin(Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(index)
                            .small()
                            .strong()
                            .color(palette.text_primary),
                    );
                });
            ui.vertical(|ui| {
                ui.label(RichText::new(title).strong().color(palette.text_primary));
                ui.label(RichText::new(body).small().color(palette.text_secondary));
            });
        });
    });
    ui.add_space(8.0);
}

fn option_from_text(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn friendly_time(timestamp: u64) -> String {
    let Some(dt) = Local.timestamp_opt(timestamp as i64, 0).single() else {
        return "--".to_string();
    };

    let now = Local::now();
    let age = now.timestamp() - dt.timestamp();

    if age < 60 {
        "刚刚".to_string()
    } else if age < 3600 {
        format!("{} 分钟前", age / 60)
    } else if age < 86_400 {
        format!("今天 {}", dt.format("%H:%M"))
    } else if age < 172_800 {
        format!("昨天 {}", dt.format("%H:%M"))
    } else {
        dt.format("%m-%d %H:%M").to_string()
    }
}

fn format_optional_timestamp(timestamp: Option<u64>) -> String {
    timestamp
        .filter(|timestamp| *timestamp > 0)
        .map(friendly_time)
        .unwrap_or_else(|| "--".to_string())
}

fn format_bytes(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = size as f64;
    let mut index = 0;

    while value >= 1024.0 && index < UNITS.len() - 1 {
        value /= 1024.0;
        index += 1;
    }

    if index == 0 {
        format!("{size} {}", UNITS[index])
    } else {
        format!("{value:.1} {}", UNITS[index])
    }
}

fn parent_remote_path(path: &str) -> String {
    let normalized = path.trim().replace('\\', "/");
    if normalized.is_empty() || normalized == "." {
        return ".".to_string();
    }
    if normalized == "/" {
        return "/".to_string();
    }

    let trimmed = normalized.trim_end_matches('/');
    match trimmed.rfind('/') {
        Some(0) => "/".to_string(),
        Some(index) => trimmed[..index].to_string(),
        None => ".".to_string(),
    }
}

fn shortcut_title(command: &str) -> String {
    let single_line = command.replace('\n', " ");
    let trimmed = single_line.trim();
    if trimmed.len() <= 24 {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..24])
    }
}
