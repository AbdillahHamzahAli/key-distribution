//! Alice (initiator) and Bob (responder) entry points.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::apps::chat::{ChatContext, ChatReason, chat_loop};
use crate::apps::common::{prompt_id, prompt_key, prompt_port, prompt_text, read_line};
use crate::crypto::codec::Key;
use crate::error::AppError;
use crate::net::framing::{LineReader, connect_timeout, send_message};
use crate::protocol::handshake::{
    make_step4, make_step5, new_nonce, parse_step2, parse_ticket, verify_step5,
};
use crate::protocol::messages::{Id, Message, MessageError};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    Alice,
    Bob,
}

pub struct HandshakeResult {
    pub conn: LineReader,
    pub session_key: Key,
    pub peer: Id,
}

#[derive(Clone)]
pub struct AliceParams {
    pub key_alice: Key,
    pub initiator: Id,
    pub responder: Id,
    pub kdc_host: String,
    pub kdc_port: u16,
    pub bob_host: String,
    pub bob_port: u16,
}

/// Run the five-step exchange from Alice's side, printing progress to stdout.
pub fn alice_handshake(params: &AliceParams) -> Result<HandshakeResult, AppError> {
    alice_handshake_with(params, &mut |line| println!("{line}"))
}

/// Run the five-step exchange from Alice's side, reporting progress through `log`.
pub fn alice_handshake_with(
    params: &AliceParams,
    log: &mut dyn FnMut(String),
) -> Result<HandshakeResult, AppError> {
    let nonce = new_nonce();

    let kdc_stream =
        connect_timeout(&params.kdc_host, params.kdc_port, CONNECT_TIMEOUT).map_err(|source| {
            AppError::Connect {
                who: "KDC",
                host: params.kdc_host.clone(),
                port: params.kdc_port,
                source,
            }
        })?;
    kdc_stream.set_read_timeout(Some(STEP_TIMEOUT))?;
    kdc_stream.set_write_timeout(Some(STEP_TIMEOUT))?;
    let mut kdc = LineReader::new(kdc_stream);

    send_message(
        kdc.stream(),
        &Message::Step1 {
            initiator: params.initiator.clone(),
            responder: params.responder.clone(),
            nonce: nonce.clone(),
        },
    )?;
    log(format!(
        "[A] STEP1 sent to KDC: ida={:?} idb={:?} n1={:?}",
        params.initiator.as_str(),
        params.responder.as_str(),
        nonce.as_str()
    ));

    let reply = kdc
        .recv_message()?
        .ok_or_else(|| AppError::Config("KDC closed connection before STEP2".into()))?;
    let (for_initiator, ticket) = match reply {
        Message::Step2 {
            for_initiator,
            ticket,
        } => (for_initiator, ticket),
        other => {
            return Err(MessageError::UnexpectedStep {
                expected: "STEP2",
                actual: other.kind(),
            }
            .into());
        }
    };

    log(format!(
        "[A] STEP2 received: hex_for_a={}",
        for_initiator.as_str()
    ));
    log(format!("[A] ticket for Bob: {}", ticket.as_str()));

    let session_key = parse_step2(
        &params.key_alice,
        &for_initiator,
        &nonce,
        Some(&params.initiator),
        Some(&params.responder),
    )?;
    log("[A] Ks acquired (kept secret)".to_string());
    drop(kdc);

    let bob_stream =
        connect_timeout(&params.bob_host, params.bob_port, CONNECT_TIMEOUT).map_err(|source| {
            AppError::Connect {
                who: "Bob",
                host: params.bob_host.clone(),
                port: params.bob_port,
                source,
            }
        })?;
    bob_stream.set_read_timeout(Some(STEP_TIMEOUT))?;
    bob_stream.set_write_timeout(Some(STEP_TIMEOUT))?;
    let mut bob = LineReader::new(bob_stream);

    send_message(
        bob.stream(),
        &Message::Step3 {
            ticket: ticket.clone(),
        },
    )?;
    log(format!("[A] STEP3 sent to Bob: ticket={}", ticket.as_str()));

    let reply = bob
        .recv_message()?
        .ok_or_else(|| AppError::Config("Bob closed connection before STEP4".into()))?;
    let step4 = match reply {
        Message::Step4 { ciphertext } => ciphertext,
        other => {
            return Err(MessageError::UnexpectedStep {
                expected: "STEP4",
                actual: other.kind(),
            }
            .into());
        }
    };

    log(format!(
        "[A] STEP4 received from Bob: hex={}",
        step4.as_str()
    ));
    let step5 = make_step5(&session_key, &step4)?;
    send_message(
        bob.stream(),
        &Message::Step5 {
            ciphertext: step5.clone(),
        },
    )?;
    log(format!("[A] STEP5 sent to Bob: hex={}", step5.as_str()));

    bob.stream().set_read_timeout(None)?;
    bob.stream().set_write_timeout(None)?;
    log("[A] handshake complete".to_string());

    Ok(HandshakeResult {
        conn: bob,
        session_key,
        peer: params.responder.clone(),
    })
}

/// Complete the exchange on Bob's side for an accepted connection.
pub fn bob_handshake(stream: TcpStream, key_bob: &Key) -> Result<HandshakeResult, AppError> {
    bob_handshake_with(stream, key_bob, &mut |line| println!("{line}"))
}

/// Complete the exchange on Bob's side, reporting progress through `log`.
pub fn bob_handshake_with(
    stream: TcpStream,
    key_bob: &Key,
    log: &mut dyn FnMut(String),
) -> Result<HandshakeResult, AppError> {
    stream.set_read_timeout(Some(STEP_TIMEOUT))?;
    stream.set_write_timeout(Some(STEP_TIMEOUT))?;

    let peer_address = stream
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "?".to_string());
    log(format!("[B] connection from {peer_address}"));

    let mut conn = LineReader::new(stream);
    let message = conn
        .recv_message()?
        .ok_or_else(|| AppError::Config("peer closed connection before STEP3".into()))?;
    let ticket = match message {
        Message::Step3 { ticket } => ticket,
        other => {
            return Err(MessageError::UnexpectedStep {
                expected: "STEP3",
                actual: other.kind(),
            }
            .into());
        }
    };

    log(format!("[B] STEP3 received: ticket={}", ticket.as_str()));
    let (session_key, initiator) = parse_ticket(key_bob, &ticket)?;
    log(format!(
        "[B] ticket decrypted: ida={:?}, Ks acquired",
        initiator.as_str()
    ));

    let (nonce, step4) = make_step4(&session_key);
    send_message(
        conn.stream(),
        &Message::Step4 {
            ciphertext: step4.clone(),
        },
    )?;
    log(format!(
        "[B] STEP4 sent: n2={} hex={}",
        nonce.as_str(),
        step4.as_str()
    ));

    let message = conn
        .recv_message()?
        .ok_or_else(|| AppError::Config("peer closed connection before STEP5".into()))?;
    let step5 = match message {
        Message::Step5 { ciphertext } => ciphertext,
        other => {
            return Err(MessageError::UnexpectedStep {
                expected: "STEP5",
                actual: other.kind(),
            }
            .into());
        }
    };

    log(format!("[B] STEP5 received: hex={}", step5.as_str()));
    if !verify_step5(&session_key, &nonce, &step5)? {
        return Err(MessageError::VerificationFailed.into());
    }
    log(format!(
        "[B] STEP5 verified with {:?} -> mutual authentication OK",
        initiator.as_str()
    ));

    conn.stream().set_read_timeout(None)?;
    conn.stream().set_write_timeout(None)?;

    Ok(HandshakeResult {
        conn,
        session_key,
        peer: initiator,
    })
}

pub fn run_peer(role: Option<PeerRole>) -> Result<(), AppError> {
    println!("{}", "=".repeat(60));
    println!("PEER -- Alice (initiator) / Bob (responder)");
    println!("{}", "=".repeat(60));

    match role {
        Some(PeerRole::Alice) => run_alice(),
        Some(PeerRole::Bob) => run_bob(),
        None => loop {
            match read_line(" [1] Alice (initiator)  [2] Bob (responder)\nmode: ") {
                Some(mode) if mode == "1" => return run_alice(),
                Some(mode) if mode == "2" => return run_bob(),
                Some(_) => println!("-> enter 1 or 2"),
                None => return Err(AppError::Config("stdin closed".into())),
            }
        },
    }
}

fn run_alice() -> Result<(), AppError> {
    let key_alice = prompt_key("Ka (your long-term key)")
        .ok_or_else(|| AppError::Config("stdin closed while reading Ka".into()))?;
    let initiator = prompt_id("Your ID")
        .ok_or_else(|| AppError::Config("stdin closed while reading your ID".into()))?;
    let responder = prompt_id("Responder ID")
        .ok_or_else(|| AppError::Config("stdin closed while reading responder ID".into()))?;
    let kdc_host = prompt_text("KDC host", Some("127.0.0.1"))
        .ok_or_else(|| AppError::Config("stdin closed while reading KDC host".into()))?;
    let kdc_port = prompt_port("KDC port", Some(9001))
        .ok_or_else(|| AppError::Config("stdin closed while reading KDC port".into()))?;
    let bob_host = prompt_text("Bob host", Some("127.0.0.1"))
        .ok_or_else(|| AppError::Config("stdin closed while reading Bob host".into()))?;
    let bob_port = prompt_port("Bob port", Some(9002))
        .ok_or_else(|| AppError::Config("stdin closed while reading Bob port".into()))?;

    let key_alice = Arc::new(Mutex::new(key_alice));

    loop {
        let params = AliceParams {
            key_alice: key_alice
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone(),
            initiator: initiator.clone(),
            responder: responder.clone(),
            kdc_host: kdc_host.clone(),
            kdc_port,
            bob_host: bob_host.clone(),
            bob_port,
        };

        match alice_handshake(&params) {
            Err(error) => {
                println!("[A] handshake failed: {error}");
                match read_line("[A] [r] retry handshake [q] quit: ") {
                    Some(choice) if choice.eq_ignore_ascii_case("r") => continue,
                    _ => break,
                }
            }
            Ok(result) => {
                let context = ChatContext {
                    conn: result.conn,
                    session_key: result.session_key,
                    peer_label: responder.as_str().to_string(),
                    longterm: Arc::clone(&key_alice),
                    key_name: "ka",
                    prompt: "[A] chat> ",
                };

                match chat_loop(context)? {
                    ChatReason::Quit => {
                        println!("[A] bye");
                        break;
                    }
                    ChatReason::Rehandshake => {
                        println!("[A] starting new handshake...");
                        continue;
                    }
                    _ => {
                        println!("[A] peer disconnected.");
                        match read_line("[A] [r] rehandshake [q] quit: ") {
                            Some(choice) if choice.eq_ignore_ascii_case("r") => continue,
                            _ => break,
                        }
                    }
                }
            }
        }
    }

    println!("[A] program finished");
    Ok(())
}

fn run_bob() -> Result<(), AppError> {
    let key_bob = Arc::new(Mutex::new(
        prompt_key("Kb (your long-term key)")
            .ok_or_else(|| AppError::Config("stdin closed while reading Kb".into()))?,
    ));
    let port = prompt_port("Listen port", Some(9002))
        .ok_or_else(|| AppError::Config("stdin closed while reading listen port".into()))?;

    let listener = TcpListener::bind(("0.0.0.0", port))?;
    println!("[B] listening on 0.0.0.0:{port}; waiting for STEP3 from Alice...");

    loop {
        let (stream, _) = listener.accept()?;
        let current_key = key_bob
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();

        match bob_handshake(stream, &current_key) {
            Err(error) => {
                println!("[B] handshake failed: {error}");
                println!("[B] still listening for the next connection...");
            }
            Ok(result) => {
                let context = ChatContext {
                    conn: result.conn,
                    session_key: result.session_key,
                    peer_label: result.peer.as_str().to_string(),
                    longterm: Arc::clone(&key_bob),
                    key_name: "kb",
                    prompt: "[B] chat> ",
                };

                if chat_loop(context)? == ChatReason::Quit {
                    println!("[B] bye");
                    break;
                }
                println!("[B] waiting for next handshake...");
            }
        }
    }

    println!("[B] program finished");
    Ok(())
}
