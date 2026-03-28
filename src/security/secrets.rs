use std::sync::{LazyLock, Mutex};

use anyhow::{Context, Result};
use keyring::{Entry, Error as KeyringError};

use crate::config::server::Server;

const SERVICE_NAME: &str = "rustssh_manager";

static KEYRING_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

pub fn store_server_password(server: &Server, password: &str) -> Result<()> {
    let password = password.trim();
    if password.is_empty() {
        return Ok(());
    }

    let _guard = KEYRING_LOCK.lock().unwrap();
    let entry = entry_for_server(server)?;
    entry
        .set_password(password)
        .with_context(|| format!("Failed to store credentials for {}", server.endpoint()))
}

pub fn load_server_password(server: &Server) -> Result<Option<String>> {
    if !server.password_in_keyring {
        return Ok(None);
    }

    let _guard = KEYRING_LOCK.lock().unwrap();
    let entry = entry_for_server(server)?;
    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(KeyringError::NoEntry) => Ok(None),
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("Failed to load credentials for {}", server.endpoint())),
    }
}

pub fn clear_server_password(server: &Server) -> Result<()> {
    let _guard = KEYRING_LOCK.lock().unwrap();
    let entry = entry_for_server(server)?;
    match entry.delete_credential() {
        Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
        Err(error) => Err(anyhow::Error::new(error))
            .with_context(|| format!("Failed to delete credentials for {}", server.endpoint())),
    }
}

fn entry_for_server(server: &Server) -> Result<Entry> {
    Entry::new(SERVICE_NAME, &server.keyring_account())
        .context("Failed to open secure credential entry")
}
