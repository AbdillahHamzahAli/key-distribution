//! Small terminal widgets shared by the TUI screens.
//!
//! The input field is intentionally ASCII-only: keys, identities, ports, and
//! chat text in this project are all ASCII, and keeping the field in-house
//! avoids a second input abstraction on top of crossterm.

use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Paragraph};

/// A single-line ASCII text field with a movable cursor and optional masking.
#[derive(Debug, Clone)]
pub struct TextField {
    chars: Vec<char>,
    cursor: usize,
    mask: bool,
    max_len: Option<usize>,
}

impl TextField {
    pub fn new(mask: bool, max_len: Option<usize>) -> Self {
        Self {
            chars: Vec::new(),
            cursor: 0,
            mask,
            max_len,
        }
    }

    pub fn with_value(value: &str, mask: bool, max_len: Option<usize>) -> Self {
        let mut field = Self::new(mask, max_len);
        field.set_value(value);
        field
    }

    pub fn value(&self) -> String {
        self.chars.iter().collect()
    }

    pub fn set_value(&mut self, value: &str) {
        self.chars.clear();
        self.cursor = 0;
        for ch in value.chars() {
            if !accept_char(ch) {
                continue;
            }
            if let Some(limit) = self.max_len
                && self.chars.len() >= limit
            {
                break;
            }
            self.chars.push(ch);
        }
        self.cursor = self.chars.len();
    }

    pub fn clear(&mut self) {
        self.chars.clear();
        self.cursor = 0;
    }

    pub fn take(&mut self) -> String {
        let value = self.value();
        self.clear();
        value
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.chars.len()
    }

    /// Apply an editing key. Returns `true` when the field changed or handled
    /// the key (useful to stop the caller from also consuming it).
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.clear();
                true
            }
            KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.delete_word_left();
                true
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.chars.remove(self.cursor);
                }
                true
            }
            KeyCode::Delete => {
                if self.cursor < self.chars.len() {
                    self.chars.remove(self.cursor);
                }
                true
            }
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                true
            }
            KeyCode::Right => {
                if self.cursor < self.chars.len() {
                    self.cursor += 1;
                }
                true
            }
            KeyCode::Home => {
                self.cursor = 0;
                true
            }
            KeyCode::End => {
                self.cursor = self.chars.len();
                true
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT)
                    && accept_char(ch) =>
            {
                self.insert_char(ch);
                true
            }
            _ => false,
        }
    }

    pub fn handle_paste(&mut self, text: &str) -> bool {
        let mut changed = false;
        for ch in text.chars() {
            if accept_char(ch) {
                if let Some(limit) = self.max_len
                    && self.chars.len() >= limit
                {
                    break;
                }
                self.chars.insert(self.cursor, ch);
                self.cursor += 1;
                changed = true;
            }
        }
        changed
    }

    /// Draw the field inside a bordered box. The cursor is only shown when
    /// `focused` is true.
    pub fn draw(&self, frame: &mut Frame, area: Rect, title: &str, focused: bool) {
        let border_style = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let block = Block::bordered()
            .title(title.to_string())
            .border_style(border_style);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        self.render_text(frame, inner, focused);
    }

    /// Draw a compact one-line field (used by the setup forms).
    pub fn draw_inline(&self, frame: &mut Frame, area: Rect, focused: bool) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        self.render_text(frame, area, focused);
    }

    fn render_text(&self, frame: &mut Frame, area: Rect, focused: bool) {
        let width = area.width as usize;
        let display: Vec<char> = if self.mask {
            vec!['*'; self.chars.len()]
        } else {
            self.chars.clone()
        };
        let offset = if self.cursor >= width {
            self.cursor + 1 - width
        } else {
            0
        };
        let start = offset.min(display.len());
        let end = (start + width).min(display.len());
        let visible: String = display[start..end].iter().collect();

        let style = if focused {
            Style::default().fg(Color::White).bg(Color::DarkGray)
        } else {
            Style::default().fg(Color::Gray)
        };
        frame.render_widget(Paragraph::new(visible).style(style), area);

        if focused {
            let column = self
                .cursor
                .saturating_sub(offset)
                .min(width.saturating_sub(1));
            frame.set_cursor_position((area.x + column as u16, area.y));
        }
    }

    fn insert_char(&mut self, ch: char) {
        if let Some(limit) = self.max_len
            && self.chars.len() >= limit
        {
            return;
        }
        self.chars.insert(self.cursor, ch);
        self.cursor += 1;
    }

    fn delete_word_left(&mut self) {
        while self.cursor > 0 && self.chars[self.cursor - 1] == ' ' {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
        while self.cursor > 0 && self.chars[self.cursor - 1] != ' ' {
            self.cursor -= 1;
            self.chars.remove(self.cursor);
        }
    }
}

fn accept_char(ch: char) -> bool {
    ch.is_ascii_graphic() || ch == ' '
}

/// Hard-wrap text to `width` columns. ASCII characters have width one.
pub fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut output = Vec::new();

    for raw_line in text.split('\n') {
        if raw_line.is_empty() {
            output.push(String::new());
            continue;
        }
        let mut current = String::new();
        let mut count = 0usize;
        for ch in raw_line.chars() {
            if count == width {
                output.push(std::mem::take(&mut current));
                count = 0;
            }
            current.push(ch);
            count += 1;
        }
        if !current.is_empty() {
            output.push(current);
        }
    }

    if output.is_empty() {
        output.push(String::new());
    }
    output
}

/// Draw a helpful message when the terminal is below the minimum size.
pub fn draw_too_small(frame: &mut Frame, area: Rect, min_width: u16, min_height: u16) {
    let text = format!("\nTerminal is too small.\nResize to at least {min_width}x{min_height}.");
    let paragraph = Paragraph::new(text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Yellow))
        .block(Block::bordered().title("key-distribution"));
    frame.render_widget(paragraph, area);
}

/// Center a rectangle inside `area`, capped at `max_width`/`max_height`.
pub fn centered_rect(area: Rect, max_width: u16, max_height: u16) -> Rect {
    let width = area.width.min(max_width).max(1);
    let height = area.height.min(max_height).max(1);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width, height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn text_field_edits_ascii_only() {
        let mut field = TextField::new(false, Some(5));
        assert!(field.handle_key(key(KeyCode::Char('a'))));
        assert!(field.handle_key(key(KeyCode::Char('b'))));
        assert_eq!(field.value(), "ab");

        field.handle_key(key(KeyCode::Left));
        field.handle_key(key(KeyCode::Char('X')));
        assert_eq!(field.value(), "aXb");

        field.handle_key(key(KeyCode::Backspace));
        assert_eq!(field.value(), "ab");
        assert_eq!(field.len(), 2);

        field.handle_key(key(KeyCode::Char('é')));
        assert_eq!(field.value(), "ab");

        field.clear();
        assert!(field.is_empty());
        assert_eq!(field.value(), "");
    }

    #[test]
    fn text_field_respects_limit() {
        let mut field = TextField::new(false, Some(3));
        for ch in "abcdef".chars() {
            field.handle_key(key(KeyCode::Char(ch)));
        }
        assert_eq!(field.value(), "abc");
    }

    #[test]
    fn text_field_masks_for_display_only() {
        let field = TextField::with_value("secret", true, None);
        assert_eq!(field.value(), "secret");
        assert!(!field.is_empty());
    }

    #[test]
    fn wrap_text_hard_wraps_and_splits_newlines() {
        assert_eq!(wrap_text("abcdef", 3), vec!["abc", "def"]);
        assert_eq!(wrap_text("ab\ncd", 5), vec!["ab", "cd"]);
        assert_eq!(wrap_text("", 5), vec![""]);
    }

    #[test]
    fn control_u_clears_field() {
        let mut field = TextField::with_value("abc", false, None);
        let event = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);
        assert!(field.handle_key(event));
        assert!(field.is_empty());
    }
}
