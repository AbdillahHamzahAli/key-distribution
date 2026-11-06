//! Full-screen encrypted chat screen.

use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};

use crate::apps::peer::HandshakeResult;
use crate::crypto::codec::Key;
use crate::crypto::modes::{decrypt_with_key, encrypt_with_key};
use crate::net::framing::{LineReader, send_message};
use crate::protocol::messages::Message;
use crate::tui::events::{NetEvent, next_session_id};
use crate::tui::log::LogPane;
use crate::tui::widgets::{TextField, centered_rect, draw_too_small};

const HELP: &str = "commands: /key rotate long-term key | /rehandshake | /help | /quit";
const MIN_WIDTH: u16 = 64;
const MIN_HEIGHT: u16 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatCommand {
    Quit,
    Rehandshake,
    Key,
    Help,
    Text(String),
}

pub fn parse_command(line: &str) -> ChatCommand {
    match line.trim() {
        "/quit" | "/exit" => ChatCommand::Quit,
        "/rehandshake" | "/reconnect" => ChatCommand::Rehandshake,
        "/key" => ChatCommand::Key,
        "/help" | "/menu" | "/?" => ChatCommand::Help,
        other => ChatCommand::Text(other.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatAction {
    None,
    Quit,
    Rehandshake,
}

pub struct ChatState {
    session: u64,
    writer: TcpStream,
    session_key: Key,
    peer: String,
    role: &'static str,
    longterm: Arc<Mutex<Key>>,
    key_name: &'static str,
    log: LogPane,
    input: TextField,
    modal: Option<KeyModal>,
    history: Vec<String>,
    history_index: Option<usize>,
    connected: bool,
}

impl ChatState {
    pub fn new(
        result: HandshakeResult,
        writer: TcpStream,
        tx: Sender<NetEvent>,
        longterm: Arc<Mutex<Key>>,
        key_name: &'static str,
        role: &'static str,
    ) -> Self {
        let HandshakeResult {
            conn,
            session_key,
            peer,
        } = result;
        let peer = peer.as_str().to_string();
        let _ = writer.set_write_timeout(Some(Duration::from_secs(10)));
        let session = next_session_id();

        let reader_key = session_key.clone();
        let reader_peer = peer.clone();
        let mut reader = conn;
        thread::spawn(move || reader_loop(&mut reader, &reader_key, reader_peer, session, tx));

        let mut log = LogPane::new();
        log.sys(format!(
            "secure channel ready with {peer}; Ks is fresh and kept out of the log"
        ));
        log.dim(HELP);

        Self {
            session,
            writer,
            session_key,
            peer,
            role,
            longterm,
            key_name,
            log,
            input: TextField::new(false, Some(4096)),
            modal: None,
            history: Vec::new(),
            history_index: None,
            connected: true,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> ChatAction {
        if self.modal.is_some() {
            return self.handle_modal_key(key);
        }

        if self.log.handle_key(key) {
            return ChatAction::None;
        }

        match key.code {
            KeyCode::Up => {
                self.history_previous();
                ChatAction::None
            }
            KeyCode::Down => {
                self.history_next();
                ChatAction::None
            }
            KeyCode::Enter => self.submit(),
            _ => {
                self.input.handle_key(key);
                ChatAction::None
            }
        }
    }

    pub fn handle_paste(&mut self, text: &str) {
        if self.modal.is_some() {
            if let Some(modal) = &mut self.modal {
                modal.input.handle_paste(text);
            }
        } else {
            self.input.handle_paste(text);
        }
    }

    pub fn on_incoming(&mut self, text: String) {
        self.log.peer(format!("[{}] {text}", self.peer));
    }

    pub fn session_id(&self) -> u64 {
        self.session
    }

    pub fn on_bye(&mut self) {
        self.connected = false;
        self.log.sys(format!(
            "{} left the chat (BYE) — /rehandshake or /quit",
            self.peer
        ));
    }

    pub fn on_disconnected(&mut self) {
        self.connected = false;
        self.log.error(format!(
            "connection to {} closed — /rehandshake or /quit",
            self.peer
        ));
    }

    pub fn on_error(&mut self, error: String) {
        self.log.error(error);
    }

    pub fn shutdown(&mut self) {
        let _ = self.writer.shutdown(Shutdown::Both);
    }

    pub fn draw(&mut self, frame: &mut Frame, area: Rect) {
        if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
            draw_too_small(frame, area, MIN_WIDTH, MIN_HEIGHT);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(5),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(area);

        self.draw_header(frame, chunks[0]);
        self.log.draw(frame, chunks[1], "Conversation");
        self.input
            .draw(frame, chunks[2], "Message   (/help for commands)", true);
        frame.render_widget(
            Paragraph::new("Enter send · ↑↓ history · PgUp/PgDn log · /key rotate key · /quit")
                .style(Style::default().fg(Color::DarkGray)),
            chunks[3],
        );

        if let Some(modal) = &self.modal {
            modal.draw(frame, area);
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .title("AES-128-CBC secure chat")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let status = if self.connected {
            Span::styled("connected", Style::default().fg(Color::Green))
        } else {
            Span::styled("disconnected", Style::default().fg(Color::Red))
        };
        let identity = Line::from(vec![
            Span::styled(
                format!("{}  ↔  {}", self.role, self.peer),
                Style::default().fg(Color::White),
            ),
            Span::raw("    "),
            Span::styled(
                format!("long-term key: {}", self.key_name),
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        let state = Line::from(vec![
            Span::styled("status: ", Style::default().fg(Color::DarkGray)),
            status,
            Span::raw("    "),
            Span::styled(
                "Ks: session key (hidden)",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        frame.render_widget(Paragraph::new(vec![identity, state]), inner);
    }

    fn submit(&mut self) -> ChatAction {
        let line = self.input.take();
        let line = line.trim().to_string();
        if line.is_empty() {
            return ChatAction::None;
        }

        self.history.push(line.clone());
        self.history_index = None;

        match parse_command(&line) {
            ChatCommand::Quit => {
                self.shutdown();
                ChatAction::Quit
            }
            ChatCommand::Rehandshake => {
                self.shutdown();
                ChatAction::Rehandshake
            }
            ChatCommand::Key => {
                self.modal = Some(KeyModal::new(self.key_name));
                ChatAction::None
            }
            ChatCommand::Help => {
                self.log.dim(HELP);
                ChatAction::None
            }
            ChatCommand::Text(text) => {
                self.send_text(&text);
                ChatAction::None
            }
        }
    }

    fn send_text(&mut self, text: &str) {
        if !self.connected {
            self.log.error("not connected — use /rehandshake or /quit");
            return;
        }

        match encrypt_with_key(&self.session_key, text) {
            Ok(ciphertext) => {
                match send_message(
                    &self.writer,
                    &Message::Msg {
                        ciphertext: ciphertext.clone(),
                    },
                ) {
                    Ok(()) => {
                        self.log.me(format!("me> {text}"));
                        self.log.dim(format!(
                            "   ciphertext (hex, IV||CT): {}",
                            ciphertext.as_str()
                        ));
                    }
                    Err(error) => {
                        self.connected = false;
                        self.log.error(format!("send failed: {error}"));
                    }
                }
            }
            Err(error) => self.log.error(format!("encryption failed: {error}")),
        }
    }

    fn history_previous(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let index = match self.history_index {
            Some(0) => 0,
            Some(index) => index - 1,
            None => self.history.len() - 1,
        };
        self.history_index = Some(index);
        self.input.set_value(&self.history[index]);
    }

    fn history_next(&mut self) {
        let Some(index) = self.history_index else {
            return;
        };
        if index + 1 < self.history.len() {
            let next = index + 1;
            self.history_index = Some(next);
            self.input.set_value(&self.history[next]);
        } else {
            self.history_index = None;
            self.input.clear();
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) -> ChatAction {
        enum Outcome {
            None,
            Cancel,
            Submit(String),
        }

        let outcome = {
            let Some(modal) = self.modal.as_mut() else {
                return ChatAction::None;
            };
            match key.code {
                KeyCode::Esc => Outcome::Cancel,
                KeyCode::Enter => Outcome::Submit(modal.input.value()),
                _ => {
                    modal.input.handle_key(key);
                    Outcome::None
                }
            }
        };

        match outcome {
            Outcome::None => {}
            Outcome::Cancel => self.modal = None,
            Outcome::Submit(value) => match Key::new(&value) {
                Ok(new_key) => {
                    *self
                        .longterm
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner()) = new_key;
                    self.log.sys(format!(
                        "{} updated (applies on the next handshake; the KDC needs the same key)",
                        self.key_name
                    ));
                    self.modal = None;
                }
                Err(error) => {
                    if let Some(modal) = &mut self.modal {
                        modal.error = Some(error.to_string());
                    }
                }
            },
        }

        ChatAction::None
    }
}

struct KeyModal {
    label: String,
    input: TextField,
    error: Option<String>,
}

impl KeyModal {
    fn new(key_name: &str) -> Self {
        Self {
            label: format!("new {key_name} — exactly 16 ASCII characters"),
            input: TextField::new(true, Some(16)),
            error: None,
        }
    }

    fn draw(&self, frame: &mut Frame, area: Rect) {
        let modal_area = centered_rect(area, 70, 9);
        frame.render_widget(Clear, modal_area);

        let block = Block::bordered()
            .title("Rotate long-term key")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(modal_area);
        frame.render_widget(block, modal_area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .split(inner);

        frame.render_widget(
            Paragraph::new(self.label.as_str()).style(Style::default().fg(Color::Gray)),
            chunks[0],
        );
        self.input.draw(frame, chunks[1], "", true);
        if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red)),
                chunks[2],
            );
        }
        frame.render_widget(
            Paragraph::new("Enter apply · Esc cancel").style(Style::default().fg(Color::DarkGray)),
            chunks[3],
        );
    }
}

fn reader_loop(
    conn: &mut LineReader,
    session_key: &Key,
    peer: String,
    session: u64,
    tx: Sender<NetEvent>,
) {
    loop {
        match conn.recv_message() {
            Ok(Some(Message::Msg { ciphertext })) => {
                match decrypt_with_key(session_key, &ciphertext) {
                    Ok(text) => {
                        if tx.send(NetEvent::ChatIncoming { session, text }).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(NetEvent::ChatError {
                            session,
                            error: format!("undecryptable message from {peer}: {error}"),
                        });
                    }
                }
            }
            Ok(Some(Message::Bye)) => {
                let _ = tx.send(NetEvent::ChatBye { session });
                return;
            }
            Ok(Some(Message::Error { message })) => {
                let _ = tx.send(NetEvent::ChatError {
                    session,
                    error: format!("peer error: {message}"),
                });
            }
            Ok(Some(other)) => {
                let _ = tx.send(NetEvent::ChatError {
                    session,
                    error: format!("unexpected {} while chatting", other.kind()),
                });
            }
            Ok(None) => {
                let _ = tx.send(NetEvent::ChatDisconnected { session });
                return;
            }
            Err(error) => {
                let _ = tx.send(NetEvent::ChatError {
                    session,
                    error: format!("connection error: {error}"),
                });
                let _ = tx.send(NetEvent::ChatDisconnected { session });
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chat_commands() {
        assert_eq!(parse_command("/quit"), ChatCommand::Quit);
        assert_eq!(parse_command(" /exit "), ChatCommand::Quit);
        assert_eq!(parse_command("/rehandshake"), ChatCommand::Rehandshake);
        assert_eq!(parse_command("/key"), ChatCommand::Key);
        assert_eq!(parse_command("/help"), ChatCommand::Help);
        assert_eq!(
            parse_command("hello bob"),
            ChatCommand::Text("hello bob".to_string())
        );
    }
}
