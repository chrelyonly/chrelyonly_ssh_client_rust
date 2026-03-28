use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const LEGACY_APP_DIR_NAME: &str = "rustssh_manager";

fn runtime_root_dir() -> PathBuf {
    env::current_dir()
        .ok()
        .or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(Path::to_path_buf))
        })
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn app_root_dir() -> PathBuf {
    runtime_root_dir()
}

pub fn config_dir() -> PathBuf {
    app_root_dir().join("config")
}

pub fn data_dir() -> PathBuf {
    app_root_dir().join("data")
}

pub fn temp_dir() -> PathBuf {
    app_root_dir().join("temp")
}

pub fn ensure_app_dirs() -> std::io::Result<()> {
    fs::create_dir_all(config_dir())?;
    fs::create_dir_all(data_dir())?;
    fs::create_dir_all(temp_dir())?;
    Ok(())
}

pub fn legacy_config_dir() -> PathBuf {
    dirs::config_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(LEGACY_APP_DIR_NAME)
}

pub fn legacy_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .or_else(dirs::home_dir)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(LEGACY_APP_DIR_NAME)
}
