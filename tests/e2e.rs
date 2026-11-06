use std::collections::BTreeMap;
use std::net::{Shutdown, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use key_distribution::apps::kdc_server::serve_listener;
use key_distribution::apps::peer::{AliceParams, alice_handshake, bob_handshake};
use key_distribution::crypto::codec::Key;
use key_distribution::crypto::modes::{decrypt_with_key, encrypt_with_key};
use key_distribution::net::framing::send_message;
use key_distribution::protocol::messages::{Id, Message};

const KA: &str = "AliceKey12345678";
const KB: &str = "BobKey1111111111";

#[test]
fn kdc_handshake_then_two_way_encrypted_chat() {
    // --- KDC -------------------------------------------------------------
    let kdc_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let kdc_port = kdc_listener.local_addr().unwrap().port();

    let mut registry = BTreeMap::new();
    registry.insert("alice".to_string(), Key::new(KA).unwrap());
    registry.insert("bob".to_string(), Key::new(KB).unwrap());
    let registry = Arc::new(Mutex::new(registry));
    let kdc_shutdown = Arc::new(AtomicBool::new(false));

    let kdc_shutdown_worker = Arc::clone(&kdc_shutdown);
    let kdc = thread::spawn(move || {
        serve_listener(kdc_listener, registry, kdc_shutdown_worker).unwrap();
    });

    // --- Bob -------------------------------------------------------------
    let bob_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let bob_port = bob_listener.local_addr().unwrap().port();

    let bob = thread::spawn(move || {
        let (stream, _) = bob_listener.accept().unwrap();
        let result = bob_handshake(stream, &Key::new(KB).unwrap()).unwrap();
        let mut conn = result.conn;

        let request = conn.recv_message().unwrap().unwrap();
        let Message::Msg { ciphertext } = request else {
            panic!("expected MSG, got {request:?}");
        };
        assert_eq!(
            decrypt_with_key(&result.session_key, &ciphertext).unwrap(),
            "hello bob"
        );

        let reply = encrypt_with_key(&result.session_key, "hello alice").unwrap();
        send_message(conn.stream(), &Message::Msg { ciphertext: reply }).unwrap();
        send_message(conn.stream(), &Message::Bye).unwrap();
    });

    // --- Alice -----------------------------------------------------------
    let params = AliceParams {
        key_alice: Key::new(KA).unwrap(),
        initiator: Id::new("alice").unwrap(),
        responder: Id::new("bob").unwrap(),
        kdc_host: "127.0.0.1".to_string(),
        kdc_port,
        bob_host: "127.0.0.1".to_string(),
        bob_port,
    };
    let alice = alice_handshake(&params).unwrap();
    let mut conn = alice.conn;

    let request = encrypt_with_key(&alice.session_key, "hello bob").unwrap();
    send_message(
        conn.stream(),
        &Message::Msg {
            ciphertext: request,
        },
    )
    .unwrap();

    let reply = conn.recv_message().unwrap().unwrap();
    let Message::Msg { ciphertext } = reply else {
        panic!("expected MSG, got {reply:?}");
    };
    assert_eq!(
        decrypt_with_key(&alice.session_key, &ciphertext).unwrap(),
        "hello alice"
    );

    let bye = conn.recv_message().unwrap().unwrap();
    assert_eq!(bye, Message::Bye);
    conn.shutdown(Shutdown::Both);

    bob.join().unwrap();
    kdc_shutdown.store(true, Ordering::SeqCst);
    kdc.join().unwrap();
}

#[test]
fn wrong_longterm_key_fails_the_handshake() {
    let kdc_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let kdc_port = kdc_listener.local_addr().unwrap().port();

    let mut registry = BTreeMap::new();
    registry.insert("alice".to_string(), Key::new(KA).unwrap());
    registry.insert("bob".to_string(), Key::new(KB).unwrap());
    let registry = Arc::new(Mutex::new(registry));
    let kdc_shutdown = Arc::new(AtomicBool::new(false));

    let kdc_shutdown_worker = Arc::clone(&kdc_shutdown);
    let kdc = thread::spawn(move || {
        serve_listener(kdc_listener, registry, kdc_shutdown_worker).unwrap();
    });

    let bob_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let bob_port = bob_listener.local_addr().unwrap().port();

    let bob = thread::spawn(move || {
        let (stream, _) = bob_listener.accept().unwrap();
        bob_handshake(stream, &Key::new("WrongBobKey12345").unwrap())
    });

    let params = AliceParams {
        key_alice: Key::new(KA).unwrap(),
        initiator: Id::new("alice").unwrap(),
        responder: Id::new("bob").unwrap(),
        kdc_host: "127.0.0.1".to_string(),
        kdc_port,
        bob_host: "127.0.0.1".to_string(),
        bob_port,
    };

    // Alice reaches Bob and sends the ticket, but Bob cannot verify STEP5 or
    // decrypt the ticket, so at least one side reports a failure.
    let alice_result = alice_handshake(&params);
    let bob_result = bob.join().unwrap();
    assert!(alice_result.is_err() || bob_result.is_err());

    kdc_shutdown.store(true, Ordering::SeqCst);
    kdc.join().unwrap();
}
