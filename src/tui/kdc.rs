//! Full-screen KDC dashboard.

use std::collections::BTreeMap;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::apps::kdc_server::serve_listener_with_logger;
use crate::crypto::codec::Key;
use crate::protocol::messages::Id;
use crate::tui::events::NetEvent;
use crate::tui::log::LogPane;
use crate::tui::setup::{FieldKind, FieldSpec, FormAction, SetupForm};
use crate::tui::widgets::{TextField, draw_too_small};

const HELP: &str = "commands: /keys | /key <ID> <new 16-char key> | /help | /quit";
const MIN_WIDTH: u16 = 72;
const MIN_HEIGHT: u16 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KdcCommand {
    Quit,
    Keys,
    Help,
    UpdateKey { identity: String, key: String },
    Unknown,
}

pub fn parse_command(line: &str) -> KdcCommand {
    let trimmed = line.trim();
    match trimmed {
        "/quit" | "/exit" => KdcCommand::Quit,
        "/keys" => KdcCommand::Keys,
        "/help" | "/?" => KdcCommand::Help,
        _ => {
            let parts: Vec<&str> = trimmed
                .splitn(3, ' ')
                .filter(|part| !part.is_empty())
                .collect();
            if parts.len() == 3 && parts[0] == "/key" {
                KdcCommand::UpdateKey {
                    identity: parts[1].to_string(),
                    key: parts[2].trim().to_string(),
                }
            } else {
                KdcCommand::Unknown
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Setup,
    Running,
}

pub struct KdcApp {
    tx: Sender<NetEvent>,
    form: SetupForm,
    phase: Phase,
    registry: Arc<Mutex<BTreeMap<String, Key>>>,
    shutdown: Arc<AtomicBool>,
    log: LogPane,
    input: TextField,
    status: String,
    handshakes: usize,
    should_quit: bool,
}

impl KdcApp {
    pub fn new(tx: Sender<NetEvent>) -> Self {
        let form = SetupForm::new(
            "KDC setup",
            "long-term keys shared with Alice and Bob",
            vec![
                FieldSpec {
                    name: "ida",
                    label: "Alice ID",
                    kind: FieldKind::Id,
                    default: "alice",
                },
                FieldSpec {
                    name: "ka",
                    label: "Ka (Alice long-term key)",
                    kind: FieldKind::Key,
                    default: "AliceKey12345678",
                },
                FieldSpec {
                    name: "idb",
                    label: "Bob ID",
                    kind: FieldKind::Id,
                    default: "bob",
                },
                FieldSpec {
                    name: "kb",
                    label: "Kb (Bob long-term key)",
                    kind: FieldKind::Key,
                    default: "BobKey1111111111",
                },
                FieldSpec {
                    name: "port",
                    label: "Listen port",
                    kind: FieldKind::Port,
                    default: "9001",
                },
            ],
        );

        Self {
            tx,
            form,
            phase: Phase::Setup,
            registry: Arc::new(Mutex::new(BTreeMap::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
            log: LogPane::new(),
            input: TextField::new(false, Some(4096)),
            status: String::new(),
            handshakes: 0,
            should_quit: false,
        }
    }

    fn start(&mut self, values: BTreeMap<String, String>) -> Result<(), String> {
        let alice_id =
            Id::new(get(&values, "ida")?).map_err(|error| format!("Alice ID: {error}"))?;
        let key_alice = Key::new(get(&values, "ka")?)
            .map_err(|error| format!("Ka (Alice long-term key): {error}"))?;
        let bob_id = Id::new(get(&values, "idb")?).map_err(|error| format!("Bob ID: {error}"))?;
        let key_bob = Key::new(get(&values, "kb")?)
            .map_err(|error| format!("Kb (Bob long-term key): {error}"))?;
        let port: u16 = get(&values, "port")?
            .parse()
            .map_err(|_| "Listen port must be a number from 1 to 65535".to_string())?;

        if alice_id == bob_id {
            return Err("Alice and Bob IDs must differ".to_string());
        }

        let listener = TcpListener::bind(("0.0.0.0", port))
            .map_err(|error| format!("cannot listen on 0.0.0.0:{port}: {error}"))?;
        let bound_port = listener
            .local_addr()
            .map(|address| address.port())
            .unwrap_or(port);

        let mut keys = BTreeMap::new();
        keys.insert(alice_id.as_str().to_string(), key_alice);
        keys.insert(bob_id.as_str().to_string(), key_bob);

        self.registry = Arc::new(Mutex::new(keys));
        self.shutdown = Arc::new(AtomicBool::new(false));
        self.status = format!("listening on 0.0.0.0:{bound_port}");
        self.handshakes = 0;
        self.log = LogPane::new();
        self.input.clear();

        {
            let keys = self
                .registry
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            for (identity, key) in keys.iter() {
                self.log.kdc(format!(
                    "[KDC] registered {identity} ({} chars)",
                    key.as_str().len()
                ));
            }
        }
        self.log.kdc(format!("[KDC] {HELP}"));
        self.log.kdc(format!("[KDC] {}", self.status));

        let tx = self.tx.clone();
        let registry = Arc::clone(&self.registry);
        let shutdown = Arc::clone(&self.shutdown);
        thread::spawn(move || {
            let tx_log = tx.clone();
            if let Err(error) =
                serve_listener_with_logger(listener, registry, shutdown, move |line| {
                    let _ = tx_log.send(NetEvent::KdcLog(line));
                })
            {
                let _ = tx.send(NetEvent::KdcLog(format!(
                    "[KDC] accept loop stopped: {error}"
                )));
            }
        });

        self.phase = Phase::Running;
        Ok(())
    }

    fn handle_command(&mut self) {
        let line = self.input.take();
        let line = line.trim().to_string();
        if line.is_empty() {
            return;
        }

        match parse_command(&line) {
            KdcCommand::Quit => {
                self.shutdown.store(true, Ordering::SeqCst);
                self.log.kdc("[KDC] shutting down");
                self.should_quit = true;
            }
            KdcCommand::Keys => {
                let keys = self
                    .registry
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                for (identity, key) in keys.iter() {
                    self.log.kdc(format!("[KDC] {identity}: {}", key.as_str()));
                }
            }
            KdcCommand::Help => self.log.kdc(format!("[KDC] {HELP}")),
            KdcCommand::UpdateKey { identity, key } => {
                let mut keys = self
                    .registry
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner());
                if !keys.contains_key(&identity) {
                    let known: Vec<&String> = keys.keys().collect();
                    self.log.error(format!(
                        "[KDC] unknown identity {identity:?}; known: {known:?}"
                    ));
                    return;
                }
                match Key::new(&key) {
                    Ok(key) => {
                        keys.insert(identity.clone(), key);
                        self.log.kdc(format!(
                            "[KDC] key for {identity:?} updated (applies to next handshake)"
                        ));
                    }
                    Err(error) => self.log.error(format!("[KDC] -> {error}")),
                }
            }
            KdcCommand::Unknown => self.log.error(format!("[KDC] unknown command; {HELP}")),
        }
    }

    fn draw_running(&mut self, frame: &mut Frame, area: Rect) {
        if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
            draw_too_small(frame, area, MIN_WIDTH, MIN_HEIGHT);
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(6),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(area);

        let header = Block::bordered()
            .title("KDC — Key Distribution Center")
            .border_style(Style::default().fg(Color::Cyan));
        let inner = header.inner(chunks[0]);
        frame.render_widget(header, chunks[0]);
        let identities = self.registry.lock().map(|keys| keys.len()).unwrap_or(0);
        let summary = vec![
            Line::from(vec![
                Span::styled("status: ", Style::default().fg(Color::DarkGray)),
                Span::styled(self.status.as_str(), Style::default().fg(Color::Green)),
            ]),
            Line::from(vec![
                Span::styled("registered: ", Style::default().fg(Color::DarkGray)),
                Span::styled(identities.to_string(), Style::default().fg(Color::White)),
                Span::styled(
                    "    handshakes served: ",
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    self.handshakes.to_string(),
                    Style::default().fg(Color::White),
                ),
            ]),
        ];
        frame.render_widget(Paragraph::new(summary), inner);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(36), Constraint::Min(30)])
            .split(chunks[1]);

        let mut registry_lines = Vec::new();
        {
            let keys = self
                .registry
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            for (identity, key) in keys.iter() {
                registry_lines.push(Line::from(vec![
                    Span::styled(identity.clone(), Style::default().fg(Color::Cyan)),
                    Span::raw("  "),
                    Span::styled(
                        "*".repeat(key.as_str().chars().count()),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]));
            }
        }
        registry_lines.push(Line::from(""));
        registry_lines.push(Line::from(Span::styled(
            "keys hidden — /keys reveals them",
            Style::default().fg(Color::DarkGray),
        )));
        frame.render_widget(
            Paragraph::new(registry_lines).block(Block::bordered().title("Registered identities")),
            body[0],
        );

        self.log.draw(frame, body[1], "Protocol log");
        self.input
            .draw(frame, chunks[2], "KDC command   (/help)", true);
        frame.render_widget(
            Paragraph::new("/keys list · /key <ID> <16-char key> rotate · /quit stop")
                .style(Style::default().fg(Color::DarkGray)),
            chunks[3],
        );
    }
}

impl crate::tui::runtime::TuiApp for KdcApp {
    fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q'))
        {
            self.shutdown.store(true, Ordering::SeqCst);
            self.should_quit = true;
            return;
        }

        match self.phase {
            Phase::Setup => match self.form.handle_key(key) {
                FormAction::Submit(values) => {
                    if let Err(error) = self.start(values) {
                        self.form.set_error(error);
                    }
                }
                FormAction::Cancel => self.should_quit = true,
                FormAction::None => {}
            },
            Phase::Running => {
                if self.log.handle_key(key) {
                    return;
                }
                match key.code {
                    KeyCode::Enter => self.handle_command(),
                    _ => {
                        self.input.handle_key(key);
                    }
                }
            }
        }
    }

    fn on_paste(&mut self, text: String) {
        match self.phase {
            Phase::Setup => self.form.handle_paste(&text),
            Phase::Running => {
                self.input.handle_paste(&text);
            }
        }
    }

    fn on_net(&mut self, event: NetEvent) {
        if let NetEvent::KdcLog(line) = event {
            if line.contains("STEP2: generated fresh Ks") {
                self.handshakes += 1;
            }
            self.log.kdc(line);
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        match self.phase {
            Phase::Setup => self.form.draw(frame, frame.area()),
            Phase::Running => self.draw_running(frame, frame.area()),
        }
    }

    fn should_quit(&self) -> bool {
        self.should_quit
    }

    fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

fn get<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing form value {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kdc_commands() {
        assert_eq!(parse_command("/quit"), KdcCommand::Quit);
        assert_eq!(parse_command("/keys"), KdcCommand::Keys);
        assert_eq!(parse_command("/help"), KdcCommand::Help);
        assert_eq!(
            parse_command("/key alice NewAliceKey12345"),
            KdcCommand::UpdateKey {
                identity: "alice".to_string(),
                key: "NewAliceKey12345".to_string(),
            }
        );
        assert_eq!(parse_command("/key alice"), KdcCommand::Unknown);
        assert_eq!(parse_command("nonsense"), KdcCommand::Unknown);
    }
}
