use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

const SETTINGS_FILE_NAME: &str = "app_settings.json";

use crate::config::paths::{config_dir, legacy_config_dir};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreset {
    #[default]
    PeachBlossom,
    Celadon,
    Vermilion,
}

impl ThemePreset {
    pub fn label(self) -> &'static str {
        match self {
            Self::PeachBlossom => "莓雾粉夜",
            Self::Celadon => "青瓷薄雾",
            Self::Vermilion => "朱砂暖夜",
        }
    }

    pub fn subtitle(self) -> &'static str {
        match self {
            Self::PeachBlossom => "偏柔和的莓粉夜色，轻盈、通透，适合日常连接与浏览。",
            Self::Celadon => "冷静通透的青绿玻璃感，更适合长时间盯着终端工作。",
            Self::Vermilion => "带一点暖调层次的深色界面，重点信息会更醒目。",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct AppSettings {
    pub theme_preset: ThemePreset,
    pub last_sync_user: Option<String>,
    pub auto_sync_on_login: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme_preset: ThemePreset::PeachBlossom,
            last_sync_user: None,
            auto_sync_on_login: true,
        }
    }
}

fn app_config_dir() -> PathBuf {
    config_dir()
}

fn settings_path() -> PathBuf {
    app_config_dir().join(SETTINGS_FILE_NAME)
}

fn legacy_settings_path() -> PathBuf {
    legacy_config_dir().join(SETTINGS_FILE_NAME)
}

pub fn load_settings() -> AppSettings {
    let primary = settings_path();
    let legacy = legacy_settings_path();
    let (path, data) = match fs::read_to_string(&primary) {
        Ok(data) => (primary, data),
        Err(_) => match fs::read_to_string(&legacy) {
            Ok(data) => (legacy, data),
            Err(_) => return AppSettings::default(),
        },
    };

    match serde_json::from_str::<AppSettings>(&data) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("解析应用设置失败 {:?}: {error}", path);
            AppSettings::default()
        }
    }
}

pub fn save_settings(settings: &AppSettings) {
    if let Err(error) = fs::create_dir_all(app_config_dir()) {
        eprintln!("创建设置目录失败: {error}");
        return;
    }

    let payload = match serde_json::to_string_pretty(settings) {
        Ok(payload) => payload,
        Err(error) => {
            eprintln!("序列化应用设置失败: {error}");
            return;
        }
    };

    if let Err(error) = fs::write(settings_path(), payload) {
        eprintln!("保存应用设置失败: {error}");
    }
}
