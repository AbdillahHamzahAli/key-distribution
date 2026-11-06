//! Newline-delimited JSON framing over TCP.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

use thiserror::Error;

use crate::protocol::messages::{Message, MessageError};

pub const MAX_LINE: usize = 65_536;

#[derive(Debug, Error)]
pub enum FramingError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("text must not contain line breaks")]
    LineBreak,
    #[error("line exceeds 65536 bytes without a newline")]
    LineTooLong,
    #[error("connection closed mid-line with {0} bytes buffered")]
    ClosedMidLine(usize),
    #[error("invalid UTF-8 on the wire: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Message(#[from] MessageError),
}

/// Connect to `host:port`, trying every resolved address with a timeout.
pub fn connect_timeout(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last_error = None;
    let mut resolved_any = false;

    for address in (host, port).to_socket_addrs()? {
        resolved_any = true;
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    if !resolved_any {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("could not resolve {host}"),
        ));
    }
    Err(last_error.expect("at least one address was tried"))
}

/// Send one line, appending the newline terminator.
pub fn send_line(stream: &TcpStream, text: &str) -> Result<(), FramingError> {
    if text.contains('\n') || text.contains('\r') {
        return Err(FramingError::LineBreak);
    }

    let mut payload = String::with_capacity(text.len() + 1);
    payload.push_str(text);
    payload.push('\n');

    let mut writer = stream;
    writer.write_all(payload.as_bytes())?;
    Ok(())
}

/// Serialize and send one protocol message.
pub fn send_message(stream: &TcpStream, message: &Message) -> Result<(), FramingError> {
    send_line(stream, &message.to_line())
}

/// A buffered reader that keeps leftover bytes between reads.
pub struct LineReader {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl LineReader {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    pub fn try_clone_stream(&self) -> io::Result<TcpStream> {
        self.stream.try_clone()
    }

    pub fn shutdown(&self, how: Shutdown) {
        let _ = self.stream.shutdown(how);
    }

    /// Read one newline-terminated line. Returns `Ok(None)` on a clean close.
    pub fn recv_line(&mut self) -> Result<Option<String>, FramingError> {
        loop {
            if let Some(position) = self.buffer.iter().position(|&byte| byte == b'\n') {
                let line: Vec<u8> = self.buffer.drain(..=position).collect();
                let text = std::str::from_utf8(&line[..line.len() - 1])?;
                return Ok(Some(text.to_string()));
            }

            if self.buffer.len() > MAX_LINE {
                self.buffer.clear();
                return Err(FramingError::LineTooLong);
            }

            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    if self.buffer.is_empty() {
                        return Ok(None);
                    }
                    let buffered = self.buffer.len();
                    self.buffer.clear();
                    return Err(FramingError::ClosedMidLine(buffered));
                }
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(FramingError::Io(error)),
            }
        }
    }

    /// Read and decode one protocol message.
    pub fn recv_message(&mut self) -> Result<Option<Message>, FramingError> {
        match self.recv_line()? {
            Some(line) => Ok(Some(Message::parse(&line)?)),
            None => Ok(None),
        }
    }
}
