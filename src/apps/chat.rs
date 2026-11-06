//! Interactive two-way encrypted chat: stdin on the main thread, network on another.

use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::apps::common::read_line;
use crate::crypto::codec::Key;
use crate::crypto::modes::{decrypt_with_key, encrypt_with_key};
use crate::error::AppError;
use crate::net::framing::{LineReader, send_message};
use crate::protocol::messages::Message;

const HELP: &str =
    "type text to send encrypted | /key (change long-term key) | /rehandshake | /help | /quit";

pub struct ChatContext {
    pub conn: LineReader,
    pub session_key: Key,
    pub peer_label: String,
    pub longterm: Arc<Mutex<Key>>,
    pub key_name: &'static str,
    pub prompt: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatReason {
    Quit,
    Rehandshake,
    PeerLeft,
    PeerGone,
}

pub fn chat_loop(context: ChatContext) -> Result<ChatReason, AppError> {
    println!("{HELP}");

    let ChatContext {
        conn,
        session_key,
        peer_label,
        longterm,
        key_name,
        prompt,
    } = context;

    let writer = conn.try_clone_stream()?;
    let stop = Arc::new(AtomicBool::new(false));
    let printer = Arc::new(Mutex::new(()));

    let receiver_stop = Arc::clone(&stop);
    let receiver_printer = Arc::clone(&printer);
    let receiver_label = peer_label.clone();
    let receiver_key = session_key.clone();
    let mut reader = conn;

    let receiver = thread::spawn(move || {
        receiver_loop(
            &mut reader,
            &receiver_key,
            &receiver_label,
            &receiver_stop,
            &receiver_printer,
        );
    });

    let reason = loop {
        if stop.load(Ordering::SeqCst) {
            break ChatReason::PeerLeft;
        }

        let Some(line) = read_line(prompt) else {
            let _ = send_message(&writer, &Message::Bye);
            break ChatReason::Quit;
        };

        if stop.load(Ordering::SeqCst) {
            break ChatReason::PeerLeft;
        }
        if line.is_empty() {
            continue;
        }

        match line.as_str() {
            "/quit" => {
                let _ = send_message(&writer, &Message::Bye);
                break ChatReason::Quit;
            }
            "/rehandshake" => {
                let _ = send_message(&writer, &Message::Bye);
                break ChatReason::Rehandshake;
            }
            "/key" => {
                change_key(&longterm, key_name);
                continue;
            }
            "/help" | "/menu" => {
                println!("{HELP}");
                continue;
            }
            text => match encrypt_with_key(&session_key, text) {
                Ok(ciphertext) => {
                    match send_message(
                        &writer,
                        &Message::Msg {
                            ciphertext: ciphertext.clone(),
                        },
                    ) {
                        Ok(()) => println!("me> sent hex {}", ciphertext.as_str()),
                        Err(error) => {
                            println!("** send failed ({error})");
                            break ChatReason::PeerGone;
                        }
                    }
                }
                Err(error) => {
                    println!("** send failed ({error})");
                    break ChatReason::PeerGone;
                }
            },
        }
    };

    stop.store(true, Ordering::SeqCst);
    let _ = writer.shutdown(Shutdown::Both);
    let _ = receiver.join();
    Ok(reason)
}

fn receiver_loop(
    reader: &mut LineReader,
    session_key: &Key,
    peer_label: &str,
    stop: &AtomicBool,
    printer: &Mutex<()>,
) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }

        match reader.recv_message() {
            Ok(Some(Message::Msg { ciphertext })) => {
                match decrypt_with_key(session_key, &ciphertext) {
                    Ok(plaintext) => async_print(printer, &format!("[{peer_label}] {plaintext}")),
                    Err(error) => {
                        async_print(printer, &format!("** undecryptable message ({error})"))
                    }
                }
            }
            Ok(Some(Message::Bye)) => {
                async_print(
                    printer,
                    &format!("** {peer_label} left the chat (BYE) (press enter)"),
                );
                break;
            }
            Ok(Some(Message::Error { message })) => {
                async_print(printer, &format!("** peer error: {message}"));
            }
            Ok(Some(other)) => {
                async_print(printer, &format!("** unexpected message: {other:?}"));
            }
            Ok(None) => {
                async_print(
                    printer,
                    &format!("** {peer_label} disconnected (press enter)"),
                );
                break;
            }
            Err(error) => {
                if !stop.load(Ordering::SeqCst) {
                    async_print(printer, &format!("** connection error ({error})"));
                }
                break;
            }
        }
    }
    stop.store(true, Ordering::SeqCst);
}

fn async_print(printer: &Mutex<()>, message: &str) {
    let _guard = printer.lock().unwrap_or_else(|poison| poison.into_inner());
    println!();
    println!("{message}");
}

fn change_key(longterm: &Mutex<Key>, key_name: &str) {
    loop {
        match read_line(&format!(
            "new {key_name} (exactly 16 ASCII chars, empty to cancel): "
        )) {
            None => {
                println!("\n** key change cancelled");
                return;
            }
            Some(value) if value.is_empty() => {
                println!("** key change cancelled");
                return;
            }
            Some(value) => match Key::new(&value) {
                Ok(key) => {
                    *longterm.lock().unwrap_or_else(|poison| poison.into_inner()) = key;
                    println!(
                        "{key_name} updated (applies on next handshake; the KDC needs the same key)"
                    );
                    return;
                }
                Err(error) => println!("-> {error}"),
            },
        }
    }
}
