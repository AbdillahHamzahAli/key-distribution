//! Interactive setup forms shown before the KDC/peer starts.

use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Paragraph};

use crate::crypto::codec::Key;
use crate::protocol::messages::Id;
use crate::tui::widgets::{TextField, centered_rect, draw_too_small};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Id,
    Key,
    Port,
}

#[derive(Debug, Clone, Copy)]
pub struct FieldSpec {
    pub name: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
    pub default: &'static str,
}

#[derive(Debug)]
struct FieldState {
    spec: FieldSpec,
    input: TextField,
}

#[derive(Debug)]
pub struct SetupForm {
    title: &'static str,
    subtitle: &'static str,
    fields: Vec<FieldState>,
    focus: usize,
    error: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FormAction {
    Submit(BTreeMap<String, String>),
    Cancel,
    None,
}

impl SetupForm {
    pub fn new(title: &'static str, subtitle: &'static str, specs: Vec<FieldSpec>) -> Self {
        let fields = specs
            .into_iter()
            .map(|spec| {
                let max_len = match spec.kind {
                    FieldKind::Key => Some(16),
                    FieldKind::Port => Some(5),
                    FieldKind::Id => Some(32),
                    FieldKind::Text => Some(64),
                };
                FieldState {
                    spec,
                    input: TextField::with_value(
                        spec.default,
                        spec.kind == FieldKind::Key,
                        max_len,
                    ),
                }
            })
            .collect();
        Self {
            title,
            subtitle,
            fields,
            focus: 0,
            error: None,
        }
    }

    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    #[cfg(test)]
    pub fn set_value(&mut self, name: &str, value: &str) {
        if let Some(field) = self.fields.iter_mut().find(|field| field.spec.name == name) {
            field.input.set_value(value);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> FormAction {
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                self.focus = (self.focus + 1) % self.fields.len();
                FormAction::None
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + self.fields.len() - 1) % self.fields.len();
                FormAction::None
            }
            KeyCode::Enter => self.validate(),
            KeyCode::Esc => FormAction::Cancel,
            _ => {
                if let Some(field) = self.fields.get_mut(self.focus) {
                    field.input.handle_key(key);
                }
                FormAction::None
            }
        }
    }

    pub fn handle_paste(&mut self, text: &str) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            field.input.handle_paste(text);
        }
    }

    fn validate(&mut self) -> FormAction {
        match self.collect() {
            Ok(values) => {
                self.error = None;
                FormAction::Submit(values)
            }
            Err(error) => {
                self.error = Some(error);
                FormAction::None
            }
        }
    }

    fn collect(&self) -> Result<BTreeMap<String, String>, String> {
        let mut values = BTreeMap::new();
        for field in &self.fields {
            let raw = field.input.value();
            let trimmed = raw.trim();
            let (name, label, kind) = (field.spec.name, field.spec.label, field.spec.kind);

            let value = match kind {
                FieldKind::Text => {
                    if trimmed.is_empty() {
                        return Err(format!("{label} must not be empty"));
                    }
                    trimmed.to_string()
                }
                FieldKind::Id => {
                    Id::new(trimmed).map_err(|error| format!("{label}: {error}"))?;
                    trimmed.to_string()
                }
                FieldKind::Key => {
                    Key::new(&raw).map_err(|error| format!("{label}: {error}"))?;
                    raw.clone()
                }
                FieldKind::Port => {
                    let port: u16 = trimmed
                        .parse()
                        .map_err(|_| format!("{label} must be a number from 1 to 65535"))?;
                    if port == 0 {
                        return Err(format!("{label} must be a number from 1 to 65535"));
                    }
                    port.to_string()
                }
            };
            values.insert(name.to_string(), value);
        }
        Ok(values)
    }

    pub fn draw(&self, frame: &mut Frame, area: Rect) {
        let min_width = 60;
        let min_height = self.fields.len() as u16 + 5;
        if area.width < min_width || area.height < min_height {
            draw_too_small(frame, area, min_width, min_height);
            return;
        }

        let form_area = centered_rect(
            area,
            area.width.min(92),
            (self.fields.len() as u16 + 4).min(area.height),
        );
        let title = if self.subtitle.is_empty() {
            self.title.to_string()
        } else {
            format!("{} — {}", self.title, self.subtitle)
        };
        let block = Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(form_area);
        frame.render_widget(block, form_area);
        if inner.height < self.fields.len() as u16 + 2 || inner.width < 20 {
            return;
        }

        let longest_label = self
            .fields
            .iter()
            .map(|field| field.spec.label.chars().count())
            .max()
            .unwrap_or(0) as u16
            + 2;
        let label_width = longest_label.min(inner.width.saturating_sub(12)).max(8);

        for (index, field) in self.fields.iter().enumerate() {
            let y = inner.y + index as u16;
            let label_area = Rect::new(inner.x, y, label_width, 1);
            let input_area = Rect::new(inner.x + label_width, y, inner.width - label_width, 1);

            let focused = index == self.focus;
            let label_style = if focused {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::Gray)
            };
            frame.render_widget(
                Paragraph::new(format!("{}:", field.spec.label)).style(label_style),
                label_area,
            );
            field.input.draw_inline(frame, input_area, focused);
        }

        let error_y = inner.y + self.fields.len() as u16;
        if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(error.as_str()).style(Style::default().fg(Color::Red)),
                Rect::new(inner.x, error_y, inner.width, 1),
            );
        }

        let footer_y = error_y + 1;
        if footer_y < inner.y + inner.height {
            frame.render_widget(
                Paragraph::new("Tab / ↑↓ move   Enter connect   Esc quit")
                    .style(Style::default().fg(Color::DarkGray)),
                Rect::new(inner.x, footer_y, inner.width, 1),
            );
        }
    }

    #[cfg(test)]
    pub fn focus_label(&self) -> Option<&'static str> {
        self.fields.get(self.focus).map(|field| field.spec.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn specs() -> Vec<FieldSpec> {
        vec![
            FieldSpec {
                name: "id",
                label: "Identity",
                kind: FieldKind::Id,
                default: "alice",
            },
            FieldSpec {
                name: "key",
                label: "Key",
                kind: FieldKind::Key,
                default: "AliceKey12345678",
            },
            FieldSpec {
                name: "port",
                label: "Port",
                kind: FieldKind::Port,
                default: "9001",
            },
        ]
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn validate_accepts_defaults() {
        let mut form = SetupForm::new("test", "", specs());
        let action = form.handle_key(key(KeyCode::Enter));
        match action {
            FormAction::Submit(values) => {
                assert_eq!(values.get("id").map(String::as_str), Some("alice"));
                assert_eq!(
                    values.get("key").map(String::as_str),
                    Some("AliceKey12345678")
                );
                assert_eq!(values.get("port").map(String::as_str), Some("9001"));
            }
            other => panic!("expected submit, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_short_key() {
        let mut form = SetupForm::new("test", "", specs());
        form.set_value("key", "short");
        assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::None);
        assert!(form.error.as_deref().unwrap_or("").contains("16"));
    }

    #[test]
    fn validate_rejects_zero_port() {
        let mut form = SetupForm::new("test", "", specs());
        form.set_value("port", "0");
        assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::None);
    }

    #[test]
    fn tab_cycles_focus() {
        let mut form = SetupForm::new("test", "", specs());
        assert_eq!(form.focus_label(), Some("Identity"));
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus_label(), Some("Key"));
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus_label(), Some("Port"));
        form.handle_key(key(KeyCode::Tab));
        assert_eq!(form.focus_label(), Some("Identity"));
    }

    #[test]
    fn draws_form_without_panicking() {
        let form = SetupForm::new("KDC setup", "", specs());
        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| form.draw(frame, frame.area()))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let rendered: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
        assert!(rendered.contains("Identity"));
        assert!(rendered.contains("Port"));
    }

    #[test]
    fn compact_form_fits_an_80x24_terminal() {
        let mut many = specs();
        many.extend([
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
        ]);
        let form = SetupForm::new("Alice setup", "initiator", many);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| form.draw(frame, frame.area()))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        let rendered: String = buffer.content().iter().map(|cell| cell.symbol()).collect();
        assert!(rendered.contains("Alice setup"));
        assert!(rendered.contains("Bob port"));
        assert!(!rendered.contains("too small"));
    }
}
