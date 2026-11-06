//! Alice (initiator) and Bob (responder) TUI flows.

use std::collections::BTreeMap;
use std::io;
use std::net::TcpListener;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::apps::peer::{
    AliceParams, HandshakeResult, PeerRole, alice_handshake_with, bob_handshake_with,
};
use crate::crypto::codec::Key;
use crate::protocol::messages::Id;
use crate::tui::chat::{ChatAction, ChatState};
use crate::tui::events::NetEvent;
use crate::tui::log::LogPane;
use crate::tui::runtime::TuiApp;
use crate::tui::setup::{FieldKind, FieldSpec, FormAction, SetupForm};
use crate::tui::widgets::{centered_rect, draw_too_small};

const MIN_WIDTH: u16 = 64;
const MIN_HEIGHT: u16 = 16;

pub struct PeerApp {
    tx: Sender<NetEvent>,
    mode: Mode,
    select_index: usize,
    alice: Option<AliceState>,
    bob: Option<BobState>,
    chat: Option<ChatState>,
    should_quit: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Select,
    Alice,
    Bob,
}

impl PeerApp {
    pub fn new(tx: Sender<NetEvent>, role: Option<PeerRole>) -> Self {
        let (mode, alice, bob) = match role {
            Some(PeerRole::Alice) => (Mode::Alice, Some(AliceState::new()), None),
            Some(PeerRole::Bob) => (Mode::Bob, None, Some(BobState::new())),
            None => (Mode::Select, None, None),
        };
        Self {
            tx,
            mode,
            select_index: 0,
            alice,
            bob,
            chat: None,
            should_quit: false,
        }
    }

    fn start_selected(&mut self) {
        match self.select_index {
            0 => {
                self.mode = Mode::Alice;
                self.alice = Some(AliceState::new());
            }
            _ => {
                self.mode = Mode::Bob;
                self.bob = Some(BobState::new());
            }
        }
    }

    fn request_quit(&mut self) {
        self.should_quit = true;
        if let Some(chat) = &mut self.chat {
            chat.shutdown();
        }
    }

    fn handle_alice_key(&mut self, key: KeyEvent) {
        if self.chat.is_some() {
            let action = self
                .chat
                .as_mut()
                .map(|chat| chat.handle_key(key))
                .unwrap_or(ChatAction::None);
            match action {
                ChatAction::None => {}
                ChatAction::Quit => self.request_quit(),
                ChatAction::Rehandshake => {
                    if let Some(chat) = &mut self.chat {
                        chat.shutdown();
                    }
                    self.chat = None;
                    let tx = self.tx.clone();
                    if let Some(alice) = &mut self.alice {
                        alice.begin_rehandshake(&tx);
                    }
                }
            }
            return;
        }

        let tx = self.tx.clone();
        if let Some(alice) = &mut self.alice
            && alice.handle_key(key, &tx)
        {
            self.should_quit = true;
        }
    }

    fn handle_bob_key(&mut self, key: KeyEvent) {
        if self.chat.is_some() {
            let action = self
                .chat
                .as_mut()
                .map(|chat| chat.handle_key(key))
                .unwrap_or(ChatAction::None);
            match action {
                ChatAction::None => {}
                ChatAction::Quit => self.request_quit(),
                ChatAction::Rehandshake => {
                    if let Some(chat) = &mut self.chat {
                        chat.shutdown();
                    }
                    self.chat = None;
                    if let Some(bob) = &mut self.bob {
                        bob.wait_for_next();
                    }
                }
            }
            return;
        }

        let tx = self.tx.clone();
        if let Some(bob) = &mut self.bob
            && bob.handle_key(key, &tx)
        {
            self.should_quit = true;
        }
    }

    fn accept_alice(&mut self, result: HandshakeResult) {
        let Some(alice) = &mut self.alice else {
            return;
        };
        let writer = match result.conn.try_clone_stream() {
            Ok(writer) => writer,
            Err(error) => {
                alice.phase = AlicePhase::Disconnected;
                alice
                    .log
                    .error(format!("could not prepare chat stream: {error}"));
                return;
            }
        };
        let longterm = Arc::clone(&alice.longterm);
        let chat = ChatState::new(result, writer, self.tx.clone(), longterm, "ka", "Alice");
        alice.phase = AlicePhase::Chat;
        alice.log.sys("handshake complete — secure chat ready");
        self.chat = Some(chat);
    }

    fn accept_bob(&mut self, result: HandshakeResult) {
        let Some(bob) = &mut self.bob else {
            return;
        };
        let writer = match result.conn.try_clone_stream() {
            Ok(writer) => writer,
            Err(error) => {
                bob.log
                    .error(format!("could not prepare chat stream: {error}"));
                bob.phase = BobPhase::Waiting;
                return;
            }
        };
        let longterm = Arc::clone(&bob.longterm);
        let chat = ChatState::new(result, writer, self.tx.clone(), longterm, "kb", "Bob");
        if let Some(old) = &mut self.chat {
            old.shutdown();
        }
        bob.phase = BobPhase::Chat;
        bob.log.sys("handshake complete — secure chat ready");
        self.chat = Some(chat);
    }
}

impl TuiApp for PeerApp {
    fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q'))
        {
            self.request_quit();
            return;
        }

        match self.mode {
            Mode::Select => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.select_index = self.select_index.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.select_index = (self.select_index + 1).min(1);
                }
                KeyCode::Char('1') => {
                    self.select_index = 0;
                    self.start_selected();
                }
                KeyCode::Char('2') => {
                    self.select_index = 1;
                    self.start_selected();
                }
                KeyCode::Enter => self.start_selected(),
                KeyCode::Esc => self.should_quit = true,
                _ => {}
            },
            Mode::Alice => self.handle_alice_key(key),
            Mode::Bob => self.handle_bob_key(key),
        }
    }

    fn on_paste(&mut self, text: String) {
        if let Some(chat) = &mut self.chat {
            chat.handle_paste(&text);
            return;
        }
        match self.mode {
            Mode::Alice => {
                if let Some(alice) = &mut self.alice {
                    alice.handle_paste(&text);
                }
            }
            Mode::Bob => {
                if let Some(bob) = &mut self.bob {
                    bob.handle_paste(&text);
                }
            }
            Mode::Select => {}
        }
    }

    fn on_net(&mut self, event: NetEvent) {
        match event {
            NetEvent::AliceLog(line) => {
                if let Some(alice) = &mut self.alice {
                    alice.log.kdc(line);
                }
            }
            NetEvent::AliceReady(result) => self.accept_alice(result),
            NetEvent::AliceFailed(error) => {
                if let Some(alice) = &mut self.alice {
                    alice.phase = AlicePhase::Disconnected;
                    alice.log.error(format!("handshake failed: {error}"));
                    alice.log.dim("press r to retry or q to quit");
                }
            }
            NetEvent::BobLog(line) => {
                if let Some(bob) = &mut self.bob {
                    bob.log.kdc(line);
                }
            }
            NetEvent::BobReady(result) => self.accept_bob(result),
            NetEvent::BobFailed(error) => {
                if let Some(bob) = &mut self.bob {
                    bob.log.error(format!("handshake failed: {error}"));
                    bob.log.sys("still listening for the next connection...");
                }
            }
            NetEvent::BobError(error) => {
                if let Some(bob) = &mut self.bob {
                    bob.log.error(error);
                }
            }
            NetEvent::KdcLog(_) => {}
            NetEvent::ChatIncoming { session, text } => {
                if let Some(chat) = &mut self.chat
                    && chat.session_id() == session
                {
                    chat.on_incoming(text);
                }
            }
            NetEvent::ChatBye { session } => {
                if let Some(chat) = &mut self.chat
                    && chat.session_id() == session
                {
                    chat.on_bye();
                }
            }
            NetEvent::ChatError { session, error } => {
                if let Some(chat) = &mut self.chat
                    && chat.session_id() == session
                {
                    chat.on_error(error);
                }
            }
            NetEvent::ChatDisconnected { session } => {
                if let Some(chat) = &mut self.chat
                    && chat.session_id() == session
                {
                    chat.on_disconnected();
                }
            }
        }
    }

    fn on_tick(&mut self) {
        if let Some(alice) = &mut self.alice {
            alice.tick = alice.tick.wrapping_add(1);
        }
        if let Some(bob) = &mut self.bob {
            bob.tick = bob.tick.wrapping_add(1);
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        match self.mode {
            Mode::Select => draw_role_select(frame, frame.area(), self.select_index),
            Mode::Alice => {
                if let Some(chat) = &mut self.chat {
                    chat.draw(frame, frame.area());
                } else if let Some(alice) = &mut self.alice {
                    alice.draw(frame, frame.area());
                }
            }
            Mode::Bob => {
                if let Some(chat) = &mut self.chat {
                    chat.draw(frame, frame.area());
                } else if let Some(bob) = &mut self.bob {
                    bob.draw(frame, frame.area());
                }
            }
        }
    }

    fn should_quit(&self) -> bool {
        self.should_quit
    }

    fn shutdown(&mut self) {
        if let Some(chat) = &mut self.chat {
            chat.shutdown();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlicePhase {
    Setup,
    Connecting,
    Chat,
    Disconnected,
}

struct AliceState {
    form: SetupForm,
    phase: AlicePhase,
    params: Option<AliceParams>,
    longterm: Arc<Mutex<Key>>,
    log: LogPane,
    tick: u64,
}

impl AliceState {
    fn new() -> Self {
        let form = SetupForm::new(
            "Alice setup",
            "initiator",
            vec![
                FieldSpec {
                    name: "ka",
                    label: "Ka (your long-term key)",
                    kind: FieldKind::Key,
                    default: "AliceKey12345678",
                },
                FieldSpec {
                    name: "ida",
                    label: "Your ID",
                    kind: FieldKind::Id,
                    default: "alice",
                },
                FieldSpec {
                    name: "idb",
                    label: "Responder ID",
                    kind: FieldKind::Id,
                    default: "bob",
                },
                FieldSpec {
                    name: "kdc_host",
                    label: "KDC host",
                    kind: FieldKind::Text,
                    default: "127.0.0.1",
                },
                FieldSpec {
                    name: "kdc_port",
                    label: "KDC port",
                    kind: FieldKind::Port,
                    default: "9001",
                },
                FieldSpec {
                    name: "bob_host",
                    label: "Bob host",
                    kind: FieldKind::Text,
                    default: "127.0.0.1",
                },
                FieldSpec {
                    name: "bob_port",
                    label: "Bob port",
                    kind: FieldKind::Port,
                    default: "9002",
                },
            ],
        );
        let longterm = Arc::new(Mutex::new(
            Key::new("AliceKey12345678").expect("default key is valid"),
        ));
        Self {
            form,
            phase: AlicePhase::Setup,
            params: None,
            longterm,
            log: LogPane::new(),
            tick: 0,
        }
    }

    fn start(
        &mut self,
        values: BTreeMap<String, String>,
        tx: &Sender<NetEvent>,
    ) -> Result<(), String> {
        let key_alice = Key::new(get(&values, "ka")?).map_err(|error| format!("Ka: {error}"))?;
        let initiator =
            Id::new(get(&values, "ida")?).map_err(|error| format!("Your ID: {error}"))?;
        let responder =
            Id::new(get(&values, "idb")?).map_err(|error| format!("Responder ID: {error}"))?;
        let kdc_host = get(&values, "kdc_host")?.to_string();
        let kdc_port = parse_port(get(&values, "kdc_port")?, "KDC port")?;
        let bob_host = get(&values, "bob_host")?.to_string();
        let bob_port = parse_port(get(&values, "bob_port")?, "Bob port")?;

        if initiator == responder {
            return Err("Your ID and the responder ID must differ".to_string());
        }

        self.params = Some(AliceParams {
            key_alice: key_alice.clone(),
            initiator,
            responder,
            kdc_host: kdc_host.clone(),
            kdc_port,
            bob_host: bob_host.clone(),
            bob_port,
        });
        self.longterm = Arc::new(Mutex::new(key_alice));
        self.log = LogPane::new();
        self.log
            .sys(format!("connecting to KDC at {kdc_host}:{kdc_port}..."));
        self.log.sys(format!(
            "after the ticket is issued I will connect to Bob at {bob_host}:{bob_port}"
        ));
        self.phase = AlicePhase::Connecting;
        self.spawn_handshake(tx);
        Ok(())
    }

    fn spawn_handshake(&mut self, tx: &Sender<NetEvent>) {
        let Some(mut params) = self.params.clone() else {
            self.phase = AlicePhase::Disconnected;
            self.log.error("missing handshake parameters");
            return;
        };
        params.key_alice = self
            .longterm
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        let tx = tx.clone();
        thread::spawn(move || {
            let tx_log = tx.clone();
            let mut logger = move |line: String| {
                let _ = tx_log.send(NetEvent::AliceLog(line));
            };
            match alice_handshake_with(&params, &mut logger) {
                Ok(result) => {
                    let _ = tx.send(NetEvent::AliceReady(result));
                }
                Err(error) => {
                    let _ = tx.send(NetEvent::AliceFailed(error.to_string()));
                }
            }
        });
    }

    fn begin_rehandshake(&mut self, tx: &Sender<NetEvent>) {
        if self.params.is_none() {
            return;
        }
        self.log.sys("starting a new handshake...");
        self.phase = AlicePhase::Connecting;
        self.spawn_handshake(tx);
    }

    /// Returns `true` when the whole app should quit.
    fn handle_key(&mut self, key: KeyEvent, tx: &Sender<NetEvent>) -> bool {
        match self.phase {
            AlicePhase::Setup => match self.form.handle_key(key) {
                FormAction::Submit(values) => {
                    if let Err(error) = self.start(values, tx) {
                        self.form.set_error(error);
                    }
                }
                FormAction::Cancel => return true,
                FormAction::None => {}
            },
            AlicePhase::Connecting => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                    return true;
                }
            }
            AlicePhase::Disconnected => match key.code {
                KeyCode::Char('r') | KeyCode::Char('R') | KeyCode::Enter => {
                    self.begin_rehandshake(tx);
                }
                KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return true,
                _ => {}
            },
            AlicePhase::Chat => {}
        }
        false
    }

    fn handle_paste(&mut self, text: &str) {
        if self.phase == AlicePhase::Setup {
            self.form.handle_paste(text);
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        match self.phase {
            AlicePhase::Setup => self.form.draw(frame, area),
            AlicePhase::Connecting => draw_status_screen(
                frame,
                area,
                &mut self.log,
                "Handshake — Alice",
                spawner_text(self.tick, "connecting to KDC and Bob..."),
                "Esc / q quit",
            ),
            AlicePhase::Disconnected => draw_status_screen(
                frame,
                area,
                &mut self.log,
                "Handshake — Alice",
                "handshake did not complete".to_string(),
                "r retry handshake · q quit",
            ),
            AlicePhase::Chat => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BobPhase {
    Setup,
    Waiting,
    Chat,
}

struct BobState {
    form: SetupForm,
    phase: BobPhase,
    longterm: Arc<Mutex<Key>>,
    log: LogPane,
    port: u16,
    tick: u64,
}

impl BobState {
    fn new() -> Self {
        let form = SetupForm::new(
            "Bob setup",
            "responder",
            vec![
                FieldSpec {
                    name: "kb",
                    label: "Kb (your long-term key)",
                    kind: FieldKind::Key,
                    default: "BobKey1111111111",
                },
                FieldSpec {
                    name: "port",
                    label: "Listen port",
                    kind: FieldKind::Port,
                    default: "9002",
                },
            ],
        );
        let longterm = Arc::new(Mutex::new(
            Key::new("BobKey1111111111").expect("default key is valid"),
        ));
        Self {
            form,
            phase: BobPhase::Setup,
            longterm,
            log: LogPane::new(),
            port: 9002,
            tick: 0,
        }
    }

    fn start(
        &mut self,
        values: BTreeMap<String, String>,
        tx: &Sender<NetEvent>,
    ) -> Result<(), String> {
        let key_bob = Key::new(get(&values, "kb")?).map_err(|error| format!("Kb: {error}"))?;
        let port = parse_port(get(&values, "port")?, "Listen port")?;

        let listener = TcpListener::bind(("0.0.0.0", port))
            .map_err(|error| format!("cannot listen on 0.0.0.0:{port}: {error}"))?;
        let bound_port = listener
            .local_addr()
            .map(|address| address.port())
            .unwrap_or(port);

        self.longterm = Arc::new(Mutex::new(key_bob));
        self.port = bound_port;
        self.log = LogPane::new();
        self.log.sys(format!(
            "listening on 0.0.0.0:{bound_port} — waiting for Alice..."
        ));
        self.log
            .dim("the KDC must have the same Kb registered for bob");

        self.phase = BobPhase::Waiting;

        let key = Arc::clone(&self.longterm);
        let tx = tx.clone();
        thread::spawn(move || bob_listener_loop(listener, key, tx));
        Ok(())
    }

    fn wait_for_next(&mut self) {
        self.phase = BobPhase::Waiting;
        self.log.sys("waiting for the next connection...");
    }

    /// Returns `true` when the whole app should quit.
    fn handle_key(&mut self, key: KeyEvent, tx: &Sender<NetEvent>) -> bool {
        match self.phase {
            BobPhase::Setup => match self.form.handle_key(key) {
                FormAction::Submit(values) => {
                    if let Err(error) = self.start(values, tx) {
                        self.form.set_error(error);
                    }
                }
                FormAction::Cancel => return true,
                FormAction::None => {}
            },
            BobPhase::Waiting => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                    return true;
                }
            }
            BobPhase::Chat => {}
        }
        false
    }

    fn handle_paste(&mut self, text: &str) {
        if self.phase == BobPhase::Setup {
            self.form.handle_paste(text);
        }
    }

    fn draw(&mut self, frame: &mut Frame, area: Rect) {
        match self.phase {
            BobPhase::Setup => self.form.draw(frame, area),
            BobPhase::Waiting => draw_status_screen(
                frame,
                area,
                &mut self.log,
                "Bob — responder",
                spawner_text(
                    self.tick,
                    &format!("listening on 0.0.0.0:{} — waiting for Alice...", self.port),
                ),
                "Esc / q quit",
            ),
            BobPhase::Chat => {}
        }
    }
}

fn bob_listener_loop(listener: TcpListener, key: Arc<Mutex<Key>>, tx: Sender<NetEvent>) {
    if let Err(error) = listener.set_nonblocking(true) {
        let _ = tx.send(NetEvent::BobError(format!(
            "listener setup failed: {error}"
        )));
        return;
    }

    loop {
        match listener.accept() {
            Ok((stream, _address)) => {
                let current = key
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .clone();
                let tx_log = tx.clone();
                let mut logger = move |line: String| {
                    let _ = tx_log.send(NetEvent::BobLog(line));
                };
                match bob_handshake_with(stream, &current, &mut logger) {
                    Ok(result) => {
                        let _ = tx.send(NetEvent::BobReady(result));
                    }
                    Err(error) => {
                        let _ = tx.send(NetEvent::BobFailed(error.to_string()));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = tx.send(NetEvent::BobError(format!("accept failed: {error}")));
                return;
            }
        }
    }
}

fn draw_role_select(frame: &mut Frame, area: Rect, selected: usize) {
    if area.width < 52 || area.height < 12 {
        draw_too_small(frame, area, 52, 12);
        return;
    }

    let box_area = centered_rect(area, 62, 11);
    let block = Block::bordered()
        .title("Choose peer role")
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(box_area);
    frame.render_widget(block, box_area);

    let options = [
        "[1] Alice — initiator (needs KDC + Bob reachable)",
        "[2] Bob — responder (listens for Alice)",
    ];
    let mut lines = vec![Line::from("")];
    for (index, option) in options.iter().enumerate() {
        let style = if index == selected {
            Style::default().fg(Color::Black).bg(Color::Cyan)
        } else {
            Style::default().fg(Color::Gray)
        };
        lines.push(Line::styled(*option, style));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        "↑↓ select · Enter confirm · Esc quit",
        Style::default().fg(Color::DarkGray),
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_status_screen(
    frame: &mut Frame,
    area: Rect,
    log: &mut LogPane,
    title: &str,
    status: String,
    footer: &str,
) {
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        draw_too_small(frame, area, MIN_WIDTH, MIN_HEIGHT);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);

    let block = Block::bordered()
        .title(title.to_string())
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(chunks[0]);
    frame.render_widget(block, chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            status,
            Style::default().fg(Color::Gray),
        ))),
        inner,
    );

    log.draw(frame, chunks[1], "Log");
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        chunks[2],
    );
}

fn spawner_text(tick: u64, text: &str) -> String {
    let spinner = match tick % 4 {
        0 => "|",
        1 => "/",
        2 => "-",
        _ => "\\",
    };
    format!("{spinner} {text}")
}

fn parse_port(value: &str, label: &str) -> Result<u16, String> {
    let port: u16 = value
        .parse()
        .map_err(|_| format!("{label} must be a number from 1 to 65535"))?;
    if port == 0 {
        return Err(format!("{label} must be a number from 1 to 65535"));
    }
    Ok(port)
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
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn render(app: &mut PeerApp) -> String {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|frame| app.draw(frame)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn role_selection_opens_alice_setup() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut app = PeerApp::new(tx, None);
        assert!(render(&mut app).contains("Choose peer role"));

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let rendered = render(&mut app);
        assert!(rendered.contains("Alice setup"));
        assert!(rendered.contains("Ka (your long-term key)"));
    }

    #[test]
    fn escape_quits_role_selection() {
        let (tx, _rx) = std::sync::mpsc::channel();
        let mut app = PeerApp::new(tx, None);
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.should_quit());
    }
}
