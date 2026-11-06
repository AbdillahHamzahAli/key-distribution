//! Scrollable protocol/chat log.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph};

use crate::tui::widgets::wrap_text;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    System,
    Me,
    Peer,
    Error,
    Kdc,
    Dim,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub kind: LogKind,
    pub text: String,
}

#[derive(Debug, Default)]
pub struct LogPane {
    entries: Vec<LogEntry>,
    offset: u16,
    follow: bool,
    max_scroll: u16,
    page: u16,
}

impl LogPane {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            offset: 0,
            follow: true,
            max_scroll: 0,
            page: 1,
        }
    }

    pub fn push(&mut self, kind: LogKind, text: impl Into<String>) {
        self.entries.push(LogEntry {
            kind,
            text: text.into(),
        });
    }

    pub fn sys(&mut self, text: impl Into<String>) {
        self.push(LogKind::System, text);
    }

    pub fn error(&mut self, text: impl Into<String>) {
        self.push(LogKind::Error, text);
    }

    pub fn kdc(&mut self, text: impl Into<String>) {
        self.push(LogKind::Kdc, text);
    }

    pub fn me(&mut self, text: impl Into<String>) {
        self.push(LogKind::Me, text);
    }

    pub fn peer(&mut self, text: impl Into<String>) {
        self.push(LogKind::Peer, text);
    }

    pub fn dim(&mut self, text: impl Into<String>) {
        self.push(LogKind::Dim, text);
    }

    /// PageUp/PageDown scroll the log. Ctrl+Home/Ctrl+End jump to the ends.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::PageUp => {
                self.follow = false;
                self.offset = self.offset.saturating_sub(self.page.max(1));
                true
            }
            KeyCode::PageDown => {
                if self.follow {
                    return true;
                }
                self.offset = self
                    .offset
                    .saturating_add(self.page.max(1))
                    .min(self.max_scroll);
                if self.offset >= self.max_scroll {
                    self.follow = true;
                }
                true
            }
            KeyCode::Home if ctrl => {
                self.follow = false;
                self.offset = 0;
                true
            }
            KeyCode::End if ctrl => {
                self.follow = true;
                true
            }
            _ => false,
        }
    }

    pub fn draw(&mut self, frame: &mut Frame, area: Rect, title: &str) {
        let block = Block::bordered()
            .title(title.to_string())
            .border_style(Style::default().fg(Color::DarkGray));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let mut lines: Vec<Line> = Vec::new();
        for entry in &self.entries {
            let style = style_for(entry.kind);
            for part in wrap_text(&entry.text, inner.width as usize) {
                lines.push(Line::styled(part, style));
            }
        }

        let max_scroll = lines.len().saturating_sub(inner.height as usize) as u16;
        self.max_scroll = max_scroll;
        self.page = inner.height;
        if self.follow {
            self.offset = max_scroll;
        } else {
            self.offset = self.offset.min(max_scroll);
        }

        let paragraph = Paragraph::new(lines).scroll((self.offset, 0));
        frame.render_widget(paragraph, inner);
    }
}

fn style_for(kind: LogKind) -> Style {
    match kind {
        LogKind::System => Style::default().fg(Color::Yellow),
        LogKind::Me => Style::default().fg(Color::Green),
        LogKind::Peer => Style::default().fg(Color::Cyan),
        LogKind::Error => Style::default().fg(Color::Red),
        LogKind::Kdc => Style::default().fg(Color::LightBlue),
        LogKind::Dim => Style::default().fg(Color::DarkGray),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_kept_in_order() {
        let mut log = LogPane::new();
        log.sys("one");
        log.me("two");
        log.error("three");
        assert_eq!(log.entries.len(), 3);
        assert_eq!(log.entries[0].kind, LogKind::System);
        assert_eq!(log.entries[2].kind, LogKind::Error);
    }

    #[test]
    fn page_keys_toggle_follow_mode() {
        let mut log = LogPane::new();
        log.page = 5;
        log.max_scroll = 10;
        log.offset = 10;
        let page_up = KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE);
        assert!(log.handle_key(page_up));
        assert!(!log.follow);
        let page_down = KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE);
        assert!(log.handle_key(page_down));
        assert!(log.follow);
    }
}
