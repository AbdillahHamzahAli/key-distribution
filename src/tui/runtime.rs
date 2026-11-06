//! Terminal lifecycle and the shared TUI event loop.

use std::io;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyEvent, KeyEventKind};

use crate::tui::events::NetEvent;

const TICK: Duration = Duration::from_millis(50);

pub trait TuiApp {
    fn on_key(&mut self, key: KeyEvent);
    fn on_paste(&mut self, _text: String) {}
    fn on_net(&mut self, event: NetEvent);
    fn on_tick(&mut self) {}
    fn draw(&mut self, frame: &mut Frame);
    fn should_quit(&self) -> bool;
    fn shutdown(&mut self) {}
}

pub fn run(app: &mut dyn TuiApp, rx: Receiver<NetEvent>) -> io::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, app, &rx);
    app.shutdown();
    ratatui::restore();
    result
}

fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut dyn TuiApp,
    rx: &Receiver<NetEvent>,
) -> io::Result<()> {
    loop {
        while let Ok(event) = rx.try_recv() {
            app.on_net(event);
        }

        if app.should_quit() {
            return Ok(());
        }

        terminal.draw(|frame| app.draw(frame))?;

        if event::poll(TICK)? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => app.on_key(key),
                Event::Paste(text) => app.on_paste(text),
                _ => {}
            }
        }

        app.on_tick();
    }
}
