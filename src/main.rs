mod audit;
mod config;
mod history;
mod security;
mod ssh;
mod ui;

use config::paths::ensure_app_dirs;
use config::storage::load_servers;
use eframe::egui;
use ui::window::App;

const APP_ICON_BYTES: &[u8] = include_bytes!("resource/icon/icon.png");

fn main() {
    if let Err(error) = ensure_app_dirs() {
        eprintln!("初始化本地目录失败: {error}");
    }
    let servers = load_servers();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1600.0, 960.0])
            .with_min_inner_size([1180.0, 760.0])
            .with_app_id("berry_ssh_terminal")
            .with_icon(load_app_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "\u{8393}\u{8393}SSH\u{7ec8}\u{7aef}",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, servers)))),
    )
    .unwrap();
}

fn load_app_icon() -> egui::IconData {
    match image::load_from_memory(APP_ICON_BYTES) {
        Ok(image) => {
            let image = image.to_rgba8();
            let width = image.width();
            let height = image.height();
            egui::IconData {
                rgba: image.into_raw(),
                width,
                height,
            }
        }
        Err(error) => {
            eprintln!("加载应用图标失败: {error}");
            egui::IconData::default()
        }
    }
}
