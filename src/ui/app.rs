use ratatui::{
    widgets::{Block, Borders, List, ListItem},
    layout::{Layout, Direction, Constraint},
    Frame,
};

use crate::config::server::Server;

pub fn draw(frame: &mut Frame, servers: &Vec<Server>) {

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30),
            Constraint::Percentage(70),
        ])
        .split(frame.size());

    let items: Vec<ListItem> = servers
        .iter()
        .map(|s| ListItem::new(s.name.clone()))
        .collect();

    let server_list = List::new(items)
        .block(Block::default().title("Servers").borders(Borders::ALL));

    frame.render_widget(server_list, chunks[0]);

    let terminal = Block::default()
        .title("Terminal")
        .borders(Borders::ALL);

    frame.render_widget(terminal, chunks[1]);
}