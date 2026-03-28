use std::fs;
use std::path::PathBuf;

use dirs::{config_dir, home_dir};
use serde::{Deserialize, Serialize};

const APP_DIR_NAME: &str = "rustssh_manager";
const SETTINGS_FILE_NAME: &str = "app_settings.json";

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
            Self::PeachBlossom => "夜樱墨",
            Self::Celadon => "青瓷夜",
            Self::Vermilion => "朱砂夜",
        }
    }

    pub fn subtitle(self) -> &'static str {
        match self {
            Self::PeachBlossom => "偏可爱的粉墨夜色，柔和又有一点氛围感。",
            Self::Celadon => "冷静通透的青绿夜幕，适合长时间盯着终端。",
            Self::Vermilion => "更有层次的暖墨暗调，重点信息会更醒目。",
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
        .or_else(home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR_NAME)
}

fn settings_path() -> PathBuf {
    app_config_dir().join(SETTINGS_FILE_NAME)
}

pub fn load_settings() -> AppSettings {
    let path = settings_path();
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(_) => return AppSettings::default(),
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
