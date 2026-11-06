//! Key Distribution Center: interactive menu plus a background accept loop.

use std::collections::BTreeMap;
use std::io;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::apps::common::{prompt_id, prompt_key, prompt_port, read_line};
use crate::crypto::codec::Key;
use crate::error::AppError;
use crate::net::framing::{LineReader, send_message};
use crate::protocol::kdc_logic::handle_step1;
use crate::protocol::messages::{Id, Message, MessageError};

const HELP: &str = "kdc commands: /keys | /key <ID> <new 16-char key> | /help | /quit";
const ACCEPT_POLL: Duration = Duration::from_millis(50);
const CONN_TIMEOUT: Duration = Duration::from_secs(5);

pub struct KdcConfig {
    pub alice_id: Id,
    pub key_alice: Key,
    pub bob_id: Id,
    pub key_bob: Key,
    pub port: u16,
}

/// Read the KDC configuration interactively, then serve requests.
pub fn run() -> Result<(), AppError> {
    println!("{}", "=".repeat(60));
    println!("KDC SERVER -- key distribution via Needham-Schroeder-ish step");
    println!("{}", "=".repeat(60));

    let alice_id = prompt_id("Alice ID")
        .ok_or_else(|| AppError::Config("stdin closed while reading Alice ID".into()))?;
    let key_alice = prompt_key(&format!("Ka (key for {})", alice_id.as_str()))
        .ok_or_else(|| AppError::Config("stdin closed while reading Ka".into()))?;

    let bob_id = loop {
        let bob_id = prompt_id("Bob ID")
            .ok_or_else(|| AppError::Config("stdin closed while reading Bob ID".into()))?;
        if bob_id != alice_id {
            break bob_id;
        }
        println!("-> Bob's ID must differ from Alice's");
    };
    let key_bob = prompt_key(&format!("Kb (key for {})", bob_id.as_str()))
        .ok_or_else(|| AppError::Config("stdin closed while reading Kb".into()))?;
    let port = prompt_port("Listen port", Some(9001))
        .ok_or_else(|| AppError::Config("stdin closed while reading port".into()))?;

    serve(KdcConfig {
        alice_id,
        key_alice,
        bob_id,
        key_bob,
        port,
    })
}

pub fn serve(config: KdcConfig) -> Result<(), AppError> {
    let mut keys = BTreeMap::new();
    keys.insert(config.alice_id.as_str().to_string(), config.key_alice);
    keys.insert(config.bob_id.as_str().to_string(), config.key_bob);
    serve_with_registry(config.port, Arc::new(Mutex::new(keys)))
}

pub fn serve_with_registry(
    port: u16,
    registry: Arc<Mutex<BTreeMap<String, Key>>>,
) -> Result<(), AppError> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    let bound_port = listener.local_addr()?.port();
    let shutdown = Arc::new(AtomicBool::new(false));

    print_registered(&registry);
    println!("[KDC] listening on 0.0.0.0:{bound_port}");
    println!("[KDC] {HELP}");

    let worker_shutdown = Arc::clone(&shutdown);
    let worker_registry = Arc::clone(&registry);
    let worker = thread::spawn(move || {
        if let Err(error) = serve_listener(listener, worker_registry, worker_shutdown) {
            eprintln!("[KDC] accept loop stopped: {error}");
        }
    });

    menu_loop(&registry, &shutdown);
    shutdown.store(true, Ordering::SeqCst);
    let _ = worker.join();
    Ok(())
}

/// Accept loop used by the interactive server and by tests.
pub fn serve_listener(
    listener: TcpListener,
    registry: Arc<Mutex<BTreeMap<String, Key>>>,
    shutdown: Arc<AtomicBool>,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, address)) => match handle_connection(stream, &registry) {
                Ok(()) => println!("[KDC] done, connection closed"),
                Err(error) => println!("[KDC] rejected {address}: {error}"),
            },
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                println!("[KDC] accept error: {error}");
                return Err(error);
            }
        }
    }

    println!("[KDC] listener closed");
    Ok(())
}

fn handle_connection(
    stream: std::net::TcpStream,
    registry: &Arc<Mutex<BTreeMap<String, Key>>>,
) -> Result<(), AppError> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(CONN_TIMEOUT))?;
    stream.set_write_timeout(Some(CONN_TIMEOUT))?;

    let peer = stream
        .peer_addr()
        .map(|address| address.to_string())
        .unwrap_or_else(|_| "?".to_string());

    let mut reader = LineReader::new(stream);
    let message = reader
        .recv_message()?
        .ok_or_else(|| AppError::Config("connection closed before STEP1".into()))?;

    let (initiator, responder, nonce) = match message {
        Message::Step1 {
            initiator,
            responder,
            nonce,
        } => (initiator, responder, nonce),
        other => {
            return Err(MessageError::UnexpectedStep {
                expected: "STEP1",
                actual: other.kind(),
            }
            .into());
        }
    };

    println!(
        "[KDC] STEP1 from {peer}: ida={:?} idb={:?} n1={:?}",
        initiator.as_str(),
        responder.as_str(),
        nonce.as_str()
    );

    let (for_initiator, ticket) = {
        let keys = registry
            .lock()
            .map_err(|_| AppError::Config("key registry poisoned".into()))?;
        handle_step1(&keys, &initiator, &responder, &nonce)?
    };

    send_message(
        reader.stream(),
        &Message::Step2 {
            for_initiator: for_initiator.clone(),
            ticket: ticket.clone(),
        },
    )?;

    println!(
        "[KDC] STEP2: generated fresh Ks (hidden); hex_for_a={}",
        for_initiator.as_str()
    );
    println!("[KDC] STEP2: hex_for_b={}", ticket.as_str());
    Ok(())
}

fn print_registered(registry: &Arc<Mutex<BTreeMap<String, Key>>>) {
    let keys = registry.lock().unwrap_or_else(|poison| poison.into_inner());
    let identities: Vec<&String> = keys.keys().collect();
    println!("[KDC] registered identities: {identities:?}");
}

fn menu_loop(registry: &Arc<Mutex<BTreeMap<String, Key>>>, shutdown: &Arc<AtomicBool>) {
    println!("{HELP}");
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        let Some(command) = read_line("kdc> ") else {
            println!("[KDC] stdin closed; server keeps running (Ctrl+C to stop)");
            while !shutdown.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(200));
            }
            break;
        };

        if command.is_empty() {
            continue;
        }

        match command.as_str() {
            "/quit" => {
                println!("[KDC] shutting down");
                break;
            }
            "/keys" => {
                let keys = registry.lock().unwrap_or_else(|poison| poison.into_inner());
                for (identity, key) in keys.iter() {
                    println!("[KDC] {identity}: {}", key.as_str());
                }
            }
            "/help" => println!("{HELP}"),
            _ => handle_menu_command(&command, registry),
        }
    }
}

fn handle_menu_command(command: &str, registry: &Arc<Mutex<BTreeMap<String, Key>>>) {
    let parts: Vec<&str> = command
        .splitn(3, ' ')
        .filter(|part| !part.is_empty())
        .collect();

    if parts.len() == 3 && parts[0] == "/key" {
        let target = parts[1];
        let new_key = parts[2].trim();
        let mut keys = registry.lock().unwrap_or_else(|poison| poison.into_inner());

        if !keys.contains_key(target) {
            let known: Vec<&String> = keys.keys().collect();
            println!("[KDC] unknown identity {target:?}; known: {known:?}");
            return;
        }

        match Key::new(new_key) {
            Ok(key) => {
                keys.insert(target.to_string(), key);
                println!("[KDC] key for {target:?} updated (applies to next handshake)");
            }
            Err(error) => println!("[KDC] -> {error}"),
        }
        return;
    }

    println!("[KDC] unknown command; {HELP}");
}
