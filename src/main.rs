mod audit;
mod config;
mod history;
mod security;
mod ssh;
mod ui;

use config::storage::load_servers;
use eframe::egui;
use ui::window::App;

fn main() {
    let servers = load_servers();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1600.0, 960.0])
            .with_min_inner_size([1180.0, 760.0])
            .with_app_id("ink_garden_ssh"),
        ..Default::default()
    };

    eframe::run_native(
        "墨园 SSH",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, servers)))),
    )
    .unwrap();
}
